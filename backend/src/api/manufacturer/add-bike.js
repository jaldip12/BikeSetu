const prisma = require('../../utils/PrismaClient');

module.exports = async function(req, res) {
    try {
        const { modalId, quantity } = req.body;

        if (!quantity || quantity < 1) {
            return res.status(400).json({ error: 'Invalid quantity. Must be a positive integer.' });
        }

        const bikeModal = await prisma.bikeModals.findUnique({
            where: { id: modalId },
        });

        if (!bikeModal) {
            return res.status(404).json({ error: 'Bike modal not found' });
        }

        const bikesToCreate = Array(quantity).fill().map(() => ({
            modalId,
            status: 'MANUFACTURING',
            arrivalDate: new Date(),
            manufacturerId: req.user.sys_id,
        }));

        const createdBikes = await prisma.bike.createMany({
            data: bikesToCreate,
        });

        res.status(201).json({
            message: `Successfully added ${createdBikes.count} bikes in manufacturing...`,
            count: createdBikes.count,
        });
    } catch (error) {
        console.error('Error adding new bikes:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
}