export function isRedirectResponse(response: Response): boolean {
  return response.status >= 300 && response.status < 400;
}

export async function rejectRedirectResponse(response: Response, source: string): Promise<Response> {
  if (!isRedirectResponse(response)) return response;

  try {
    await response.body?.cancel();
  } catch {
    // The response is being rejected regardless of whether its body can be cancelled.
  }
  throw new Error(`${source} redirected; redirects are not allowed`);
}
