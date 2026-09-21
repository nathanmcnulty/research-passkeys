let operationTail: Promise<void> = Promise.resolve();

export function runSerializedCredentialMutation<TResult>(operation: () => Promise<TResult>): Promise<TResult> {
  const result = operationTail.then(operation, operation);
  operationTail = result.then(
    () => undefined,
    () => undefined
  );
  return result;
}
