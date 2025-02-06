const prisma = require('../../utils/PrismaClient');

module.exports = async function(req, res) {
    try {
        const { id } = req.params;

        const bike = await prisma.bike.findUnique({
            where: { id: Number(id) },
            include: {
                brand: true,
            },
        });

        if (!bike) {
            return res.status(404).json({ error: 'Bike not found' });
        }

        res.json(bike);
    } catch (error) {
        console.error('Error fetching bike:', error);
        res.status(500).json({ error: 'An error occurred while fetching the bike' });
    }
}
