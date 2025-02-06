const prisma = require('../../utils/PrismaClient');

module.exports = async function(req, res)  {
    try {
        const { id } = req.params;
        const { newStatus } = req.body;

        const bike = await prisma.bike.findUnique({ where: { id: Number(id) } });

        if (!bike) {
            return res.status(404).json({ error: 'Bike not found' });
        }

        if (
            (bike.status === 'IN_TRANSIT_TO_YARD' && newStatus === 'AT_BIKESETU_YARD') ||
            (bike.status === 'AT_BIKESETU_YARD' && newStatus === 'IN_TRANSIT_TO_FRANCHISEE')
        ) {
            const updatedBike = await prisma.bike.update({
                where: { id: Number(id) },
                data: {
                    status: newStatus,
                    bikesetuYardId: newStatus === 'AT_BIKESETU_YARD' ? req.user.sys_id : undefined,
                    arrivalDate: newStatus === 'AT_BIKESETU_YARD' ? new Date() : bike.arrivalDate,
                    departureDate: newStatus === 'IN_TRANSIT_TO_FRANCHISEE' ? new Date() : bike.departureDate,
                    franchiseeId: newStatus === 'IN_TRANSIT_TO_FRANCHISEE' ? "cm0pa3an800011oomozizk53z" : undefined,
                },
                include: {
                    modal: {
                        include: {
                            brand: true
                        }
                    }
                }
            });

            res.json(updatedBike);
        } else {
            res.status(400).json({ error: 'Invalid status transition' });
        }
    } catch (error) {
        console.error('Error updating bike status:', error);
        res.status(500).json({ error: 'An error occurred while updating the bike status' });
    }
}
