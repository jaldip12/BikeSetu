const prisma = require('../../utils/PrismaClient');

module.exports = async function(req, res)  {
    try {
        const { bikeId } = req.params;
        const { status } = req.body;

        const bike = await prisma.bike.findUnique({
            where: { id: Number(bikeId) },
        });

        if (!bike) {
            return res.status(404).json({ error: 'Bike not found' });
        }

        if (bike.status !== 'MANUFACTURING' && status === 'MANUFACTURED') {
            return res.status(400).json({ error: 'Can only update to MANUFACTURED status from MANUFACTURING status' });
        }

        const updatedBike = await prisma.bike.update({
            where: { id: Number(bikeId) },
            data: {
                status,
                departureDate: status === 'MANUFACTURED' ? new Date() : undefined,
                bikesetuYardId: status === 'IN_TRANSIT_TO_YARD' ? "cm0pn98g10001l1pv2xem0smx" : undefined,
            },
            include: {
                modal: {
                    include: {
                        brand: true
                    }
                }
            }
        });

        console.log('Updated bike status:', updatedBike);
        

        res.json(updatedBike);
    } catch (error) {
        console.error('Error updating bike status:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
}
