const { z } = require("zod");

const addBikeSchema = z.object({
    modalId: z.string({ required_error: "Modal ID is required" }).trim(),
    manufacturerId: z.string({ required_error: "Manufacturer ID is required" }).trim(),
    currentLocation: z.string({ required_error: "Current location is required" }).trim()
});

module.exports = {
    addBikeSchema
}
