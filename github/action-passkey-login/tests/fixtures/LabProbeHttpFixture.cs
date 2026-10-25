// Synthetic in-process HTTP fixtures. This handler never delegates to a real
// handler, opens a socket, resolves a host, or calls base.SendAsync.
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace LabProbeOfflineFixtures
{
    public sealed class ProbeReadStream : Stream
    {
        private readonly byte[] data;
        private int position;
        public bool ThrowOnRead { get; set; }
        public bool CancelOnRead { get; set; }
        public bool ThrowOnDispose { get; set; }
        public int? ReportedReadCount { get; set; }
        public readonly List<string> DisposeEvents;
        public bool WaitForCancellation { get; set; }
        public bool CancellationObserved { get; private set; }
        public bool WatchdogElapsed { get; private set; }
        public bool LastReadCanBeCanceled { get; private set; }
        public CancellationToken LastReadToken { get; private set; }
        public bool WasDisposed { get; private set; }
        public int ReadCalls { get; private set; }
        public int BytesRead { get; private set; }

        public ProbeReadStream(byte[] bytes, List<string> disposeEvents = null)
        {
            data = bytes ?? Array.Empty<byte>();
            DisposeEvents = disposeEvents ?? new List<string>();
        }
        public override bool CanRead { get { return !WasDisposed; } }
        public override bool CanSeek { get { return false; } }
        public override bool CanWrite { get { return false; } }
        public override long Length { get { throw new NotSupportedException(); } }
        public override long Position { get { return position; } set { throw new NotSupportedException(); } }

        public override int Read(byte[] buffer, int offset, int count)
        {
            ReadCalls++;
            if (WasDisposed) { throw new ObjectDisposedException(nameof(ProbeReadStream)); }
            if (ThrowOnRead) { throw new IOException("fixture-sensitive-stream-body"); }
            if (ReportedReadCount.HasValue) { return ReportedReadCount.Value; }
            int length = Math.Min(count, data.Length - position);
            Array.Copy(data, position, buffer, offset, length);
            position += length;
            BytesRead += length;
            return length;
        }

        public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            LastReadCanBeCanceled = cancellationToken.CanBeCanceled;
            LastReadToken = cancellationToken;
            if (CancelOnRead)
            {
                ReadCalls++;
                throw new OperationCanceledException("fixture-sensitive-read-cancellation", cancellationToken);
            }
            if (!WaitForCancellation) { return Read(buffer, offset, count); }
            ReadCalls++;
            // The production helper supplies its real 30-second cancellation
            // token. The independent watchdog bounds a broken implementation
            // without making a real HTTP request or hanging the suite forever.
            Task canceled = Task.Delay(Timeout.Infinite, cancellationToken);
            Task watchdog = Task.Delay(TimeSpan.FromSeconds(40));
            if (await Task.WhenAny(canceled, watchdog).ConfigureAwait(false) == watchdog)
            {
                WatchdogElapsed = true;
                throw new IOException("fixture-watchdog: production cancellation was not enforced");
            }
            try { await canceled.ConfigureAwait(false); }
            catch (OperationCanceledException)
            {
                CancellationObserved = cancellationToken.IsCancellationRequested;
                throw;
            }
            return 0;
        }

        protected override void Dispose(bool disposing)
        {
            WasDisposed = true;
            DisposeEvents.Add("Stream");
            if (ThrowOnDispose) { throw new IOException("fixture-sensitive-stream-disposal"); }
            base.Dispose(disposing);
        }
        public override void Flush() { throw new NotSupportedException(); }
        public override long Seek(long offset, SeekOrigin origin) { throw new NotSupportedException(); }
        public override void SetLength(long value) { throw new NotSupportedException(); }
        public override void Write(byte[] buffer, int offset, int count) { throw new NotSupportedException(); }
    }

    public sealed class ProbeStreamContent : StreamContent
    {
        public bool WasDisposed { get; private set; }
        public bool CancelStreamCreation { get; set; }
        public bool ThrowOnStreamCreation { get; set; }
        public bool ThrowOnDispose { get; set; }
        public int StreamCreationCalls { get; private set; }
        private readonly List<string> disposeEvents;
        public bool StreamCreationCanBeCanceled { get; private set; }
        public CancellationToken StreamCreationToken { get; private set; }
        public ProbeStreamContent(ProbeReadStream stream) : base(stream) { disposeEvents = stream.DisposeEvents; }
        protected override Task<Stream> CreateContentReadStreamAsync(CancellationToken cancellationToken)
        {
            StreamCreationCalls++;
            StreamCreationCanBeCanceled = cancellationToken.CanBeCanceled;
            StreamCreationToken = cancellationToken;
            if (ThrowOnStreamCreation)
            {
                return Task.FromException<Stream>(new IOException("fixture-sensitive-stream-creation"));
            }
            if (CancelStreamCreation)
            {
                // Synthetic cancellation tests the production error/disposal
                // path, not the actual elapsed stream-creation timeout.
                return Task.FromException<Stream>(new OperationCanceledException("fixture-sensitive-stream-creation", cancellationToken));
            }
            return base.CreateContentReadStreamAsync(cancellationToken);
        }
        protected override void Dispose(bool disposing)
        {
            WasDisposed = true;
            disposeEvents.Add("ResponseContent");
            if (ThrowOnDispose) { throw new IOException("fixture-sensitive-content-disposal"); }
            base.Dispose(disposing);
        }
    }

    // Installed only by an explicit disposal test, after the fake handler has
    // captured the original request. The native request object still owns the
    // Dispose call, and this content does not open any network path.
    public sealed class ProbeRequestDisposeContent : ByteArrayContent
    {
        public bool WasDisposed { get; private set; }
        public bool ThrowOnDispose { get; set; }
        private readonly List<string> disposeEvents;
        public ProbeRequestDisposeContent(List<string> events) : base(Array.Empty<byte>()) { disposeEvents = events; }
        protected override void Dispose(bool disposing)
        {
            WasDisposed = true;
            disposeEvents.Add("RequestContent");
            if (ThrowOnDispose) { throw new IOException("fixture-sensitive-request-disposal"); }
            base.Dispose(disposing);
        }
    }

    public sealed class ProbeHttpHandler : HttpMessageHandler
    {
        public readonly List<string> DisposeEvents = new List<string>();
        public readonly ProbeReadStream Stream;
        public readonly ProbeStreamContent Content;
        public readonly HttpResponseMessage Response;
        public readonly Dictionary<string, string> RequestHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        public readonly Dictionary<string, string> RequestContentHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        public bool ThrowOnSend { get; set; }
        public bool CancelOnSend { get; set; }
        public bool ThrowOnDispose { get; set; }
        public bool InjectRequestContent { get; set; }
        public bool ThrowOnRequestContentDispose { get; set; }
        public ProbeRequestDisposeContent InjectedRequestContent { get; private set; }
        public bool WasDisposed { get; private set; }
        public bool SendTokenCanBeCanceled { get; private set; }
        public int SendCalls { get; private set; }
        public Uri RequestUri { get; private set; }
        public string RequestMethod { get; private set; }
        public string RequestBody { get; private set; }
        public HttpRequestMessage Request { get; private set; }
        public HttpContent RequestContent { get; private set; }

        public ProbeHttpHandler(byte[] bytes)
        {
            Stream = new ProbeReadStream(bytes, DisposeEvents);
            Content = new ProbeStreamContent(Stream);
            Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");
            Response = new HttpResponseMessage(HttpStatusCode.OK) { Content = Content };
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            SendCalls++;
            SendTokenCanBeCanceled = cancellationToken.CanBeCanceled;
            Request = request;
            RequestUri = request.RequestUri;
            RequestMethod = request.Method.Method;
            foreach (var header in request.Headers) { RequestHeaders[header.Key] = string.Join("|", header.Value); }
            RequestContent = request.Content;
            if (request.Content != null)
            {
                foreach (var header in request.Content.Headers) { RequestContentHeaders[header.Key] = string.Join("|", header.Value); }
                RequestBody = await request.Content.ReadAsStringAsync().ConfigureAwait(false);
            }
            if (InjectRequestContent)
            {
                if (request.Content != null) { throw new InvalidOperationException("Disposal fixture requires an empty GET request."); }
                InjectedRequestContent = new ProbeRequestDisposeContent(DisposeEvents) { ThrowOnDispose = ThrowOnRequestContentDispose };
                request.Content = InjectedRequestContent;
            }
            if (ThrowOnSend) { throw new HttpRequestException("fixture-sensitive-request-and-response"); }
            if (CancelOnSend) { throw new TaskCanceledException("fixture-sensitive-send-cancellation"); }
            Response.RequestMessage = request;
            return Response;
        }

        protected override void Dispose(bool disposing)
        {
            WasDisposed = true;
            DisposeEvents.Add("Handler");
            if (ThrowOnDispose) { throw new IOException("fixture-sensitive-handler-disposal"); }
            base.Dispose(disposing);
        }
    }
}
