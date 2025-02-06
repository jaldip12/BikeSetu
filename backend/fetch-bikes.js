const { PrismaClient } = require('@prisma/client');
const fs = require('fs').promises;
const path = require('path');

const prisma = new PrismaClient();

async function readJsonFile(filename) {
    const data = await fs.readFile(filename, 'utf8');
    return JSON.parse(data);
}

function parsePrice(priceString) {
    // Remove non-digit characters and divide by 100 to remove extra zeros
    return Math.round(parseInt(priceString.replace(/[^\d]/g, '')) / 100);
}

async function getOrCreateBrand(brandName) {
    let brand = await prisma.brand.findUnique({ where: { name: brandName } });
    if (!brand) {
        brand = await prisma.brand.create({ data: { name: brandName } });
    }
    return brand;
}

async function insertBikeModal(bikeData) {
    try {
        const brand = await getOrCreateBrand(bikeData.brandName);

        const bikeModal = await prisma.bikeModals.create({
            data: {
                name: bikeData.modelName,
                description: bikeData.modelSummary,
                price: parsePrice(bikeData.xShowroomPrice),
                image: bikeData.modelImage,
                topSpeed: parseInt(bikeData.modelSpeed),
                range: parseInt(bikeData.modelRange),
                chargingTime: parseInt(bikeData.chargingTime),
                weight: parseInt(bikeData.Weight),
                brandId: brand.id,
            },
        });
        console.log(`Inserted bike modal: ${bikeModal.name}`);
    } catch (error) {
        console.error(`Error inserting bike modal: ${bikeData.modelName}`, error);
    }
}

async function insertAllBikeModals() {
    try {
        for (let i = 1; i <= 15; i++) {
            const filename = path.join(__dirname, `bikes/b${i}.json`);
            const jsonData = await readJsonFile(filename);

            if (jsonData.success && Array.isArray(jsonData.data)) {
                for (const bikeData of jsonData.data) {
                    await insertBikeModal(bikeData);
                }
            } else {
                console.error(`Invalid data format in file b${i}.json`);
            }
        }
    } catch (error) {
        console.error('Error inserting bike modals:', error);
    } finally {
        await prisma.$disconnect();
    }
}

insertAllBikeModals();
