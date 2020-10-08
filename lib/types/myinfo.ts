export interface IMyInfoSpec {
  attributes: {
    basic: string[]
    income: string[]
  }
  personas: Record<string, unknown>
}
