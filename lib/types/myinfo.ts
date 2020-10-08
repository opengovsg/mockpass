export interface IMyInfoSpec {
  attributes: {
    basic: string[]
    income: string[]
  }
  // eslint-disable-next-line @typescript-eslint/ban-types
  personas: Record<string, object>
}
