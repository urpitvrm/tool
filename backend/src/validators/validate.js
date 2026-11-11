export function validate(schema, data) {
  const result = schema.safeParse(data);
  if (!result.success) {
    throw Object.assign(new Error(result.error.issues.map((issue) => issue.message).join('; ')), { status: 422 });
  }
  return result.data;
}
