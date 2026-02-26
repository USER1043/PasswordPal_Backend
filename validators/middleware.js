// validators/middleware.js
// Reusable Express middleware for Joi schema validation.
// Keeps controller logic clean — validation errors return 400 with Joi details.

/**
 * Creates an Express middleware that validates a request property against a Joi schema.
 *
 * @param {import('joi').ObjectSchema} schema - The Joi schema to validate against.
 * @param {'body' | 'query' | 'params'} [source='body'] - Which part of the request to validate.
 * @returns {import('express').RequestHandler} Express middleware function.
 *
 * @example
 * // Validate request body
 * router.post('/sync', verifySession, validateRequest(pushSyncSchema, 'body'), pushController);
 *
 * // Validate query params
 * router.get('/sync', verifySession, validateRequest(pullSyncSchema, 'query'), pullController);
 */
export function validateRequest(schema, source = 'body') {
    return (req, res, next) => {
        const dataToValidate = req[source];

        const { error, value } = schema.validate(dataToValidate, {
            abortEarly: false,    // Report all errors, not just the first
            stripUnknown: true,   // Remove fields not in the schema
            convert: true,        // Allow type coercion (e.g. string → date)
        });

        if (error) {
            const details = error.details.map((d) => ({
                field: d.path.join('.'),
                message: d.message,
            }));

            return res.status(400).json({
                error: 'Validation failed',
                details,
            });
        }

        // Replace the source with the validated (and cleaned) value
        req[source] = value;
        next();
    };
}
