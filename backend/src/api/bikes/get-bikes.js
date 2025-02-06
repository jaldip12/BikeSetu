const prisma = require('../../utils/PrismaClient');

module.exports = async function(req, res) {
    try {
        const { status, page = 1, limit = 10 } = req.query;
        const skip = (page - 1) * limit;

        const whereClause = status ? { status } : {};

        const bikes = await prisma.bikeModals.findMany({
            where: whereClause,
            include: {
                brand: true
            },
            skip,
            take: Number(limit),
        });

        const total = await prisma.bike.count({ where: whereClause });

        res.json({
            bikes,
            pagination: {
                currentPage: Number(page),
                totalPages: Math.ceil(total / limit),
                totalItems: total,
            },
        });
    } catch (error) {
        console.error('Error fetching bikes:', error);
        res.status(500).json({ error: 'An error occurred while fetching bikes' });
    }
}
