// Railway Database Fix Script
// Run this with: railway run node fix_via_railway.js

const { Client } = require('pg');

async function runDatabaseFix() {
    const client = new Client({
        connectionString: process.env.DATABASE_URL
    });

    try {
        console.log('🔄 Connecting to Railway database...');
        await client.connect();
        console.log('✅ Connected to database');

        // Step 1: Add estado_codigo column
        console.log('🔄 Adding estado_codigo column...');
        await client.query(`
            ALTER TABLE documents ADD COLUMN IF NOT EXISTS estado_codigo TEXT;
        `);
        console.log('✅ Column added');

        // Step 2: Update state codes
        console.log('🔄 Standardizing state codes...');
        await client.query(`
            UPDATE documents SET estado_codigo = CASE
                WHEN estado = 'Acre' THEN 'AC'
                WHEN estado = 'Alagoas' THEN 'AL'
                WHEN estado = 'Amapá' THEN 'AP'
                WHEN estado = 'Amazonas' THEN 'AM'
                WHEN estado = 'Bahia' THEN 'BA'
                WHEN estado = 'Ceará' THEN 'CE'
                WHEN estado = 'Distrito Federal' THEN 'DF'
                WHEN estado = 'Espírito Santo' THEN 'ES'
                WHEN estado = 'Goiás' THEN 'GO'
                WHEN estado = 'Maranhão' THEN 'MA'
                WHEN estado = 'Mato Grosso' THEN 'MT'
                WHEN estado = 'Mato Grosso do Sul' THEN 'MS'
                WHEN estado = 'Minas Gerais' THEN 'MG'
                WHEN estado = 'Pará' THEN 'PA'
                WHEN estado = 'Paraíba' THEN 'PB'
                WHEN estado = 'Paraná' THEN 'PR'
                WHEN estado = 'Pernambuco' THEN 'PE'
                WHEN estado = 'Piauí' THEN 'PI'
                WHEN estado = 'Rio de Janeiro' THEN 'RJ'
                WHEN estado = 'Rio Grande do Norte' THEN 'RN'
                WHEN estado = 'Rio Grande do Sul' THEN 'RS'
                WHEN estado = 'Rondônia' THEN 'RO'
                WHEN estado = 'Roraima' THEN 'RR'
                WHEN estado = 'Santa Catarina' THEN 'SC'
                WHEN estado = 'São Paulo' THEN 'SP'
                WHEN estado = 'Sergipe' THEN 'SE'
                WHEN estado = 'Tocantins' THEN 'TO'
                WHEN estado IN ('AC', 'AL', 'AP', 'AM', 'BA', 'CE', 'DF', 'ES', 'GO', 'MA', 
                               'MT', 'MS', 'MG', 'PA', 'PB', 'PR', 'PE', 'PI', 'RJ', 'RN', 
                               'RS', 'RO', 'RR', 'SC', 'SP', 'SE', 'TO') THEN estado
                WHEN estado IN ('Federal', 'Brasil', 'BR', 'Brazil') THEN 'BR'
                ELSE estado
            END
            WHERE estado IS NOT NULL;
        `);
        console.log('✅ State codes standardized');

        // Step 3: Verification
        console.log('🔄 Verifying state distribution...');
        const result = await client.query(`
            SELECT 
                estado_codigo,
                estado,
                COUNT(*) as document_count
            FROM documents 
            WHERE estado_codigo IS NOT NULL 
            GROUP BY estado_codigo, estado 
            ORDER BY document_count DESC;
        `);

        console.log('📊 Final state distribution:');
        result.rows.forEach(row => {
            console.log(`  ${row.estado_codigo} (${row.estado}): ${row.document_count} documents`);
        });

        console.log(`\n✅ Database fix complete! Found ${result.rows.length} states with documents.`);
        console.log('🗺️ The map should now display correctly with all states!');

    } catch (error) {
        console.error('❌ Error:', error.message);
        process.exit(1);
    } finally {
        await client.end();
        console.log('🔐 Database connection closed');
    }
}

runDatabaseFix();