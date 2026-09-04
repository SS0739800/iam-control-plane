// Joins class names together, skipping any falsy ones. Handy for conditional classes
// now that we're not using Tailwind's string-template tricks anymore.
type ClassValue = string | false | null | undefined

export function cx(...values: ClassValue[]): string {
  return values.filter(Boolean).join(' ')
}
