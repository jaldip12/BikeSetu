const prisma = require('../../utils/PrismaClient');

module.exports = async function(req, res)  {
    try {
        const { status } = req.query;

        console.log('Fetching franchisee bikes:', req.user.sys_id, status);

        const bikes = await prisma.bike.findMany({
            where: {
                franchiseeId: req.user.sys_id,
                status: status ? status : undefined,
            },
            include: {
                modal: {
                    include: {
                        brand: true
                    }
                },
            },
        });

        res.json(bikes);
    } catch (error) {
        console.error('Error fetching franchisee bikes:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
}
