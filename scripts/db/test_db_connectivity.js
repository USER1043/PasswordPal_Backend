import 'dotenv/config';
import { supabase } from '../../config/db.js';

async function testDatabaseCRUD() {
    console.log('🚀 Starting Database Connectivity & CRUD Test...');

    // 1. Check Environment Variables
    const url = process.env.SUPABASE_URL;
    const key = process.env.SUPABASE_SECRET_KEY;
    
    if (!url || !key) {
        console.error('❌ Missing .env variables: SUPABASE_URL or SUPABASE_SECRET_KEY');
        process.exit(1);
    }
    console.log('✅ Environment variables loaded.');

    const timestamp = Date.now();
    const testEmail = `test_conn_${timestamp}@example.com`;
    const mockData = {
        email: testEmail,
        salt: 'mock_salt_value_12345',
        server_hash: 'mock_server_hash_argon2id',
        wrapped_mek: 'mock_wrapped_mek'
    };

    try {
        // 2. Test INSERT (Create)
        console.log(`\nTesting INSERT operation for user: ${testEmail}...`);
        const { data: insertData, error: insertError } = await supabase
            .from('users')
            .insert([mockData])
            .select()
            .single();

        if (insertError) throw new Error(`INSERT failed: ${insertError.message}`);
        console.log('✅ INSERT successful. Created User ID:', insertData.id);


        // 3. Test SELECT (Read)
        console.log(`\nTesting SELECT operation...`);
        const { data: selectData, error: selectError } = await supabase
            .from('users')
            .select('email, salt, server_hash')
            .eq('id', insertData.id)
            .single();

        if (selectError) throw new Error(`SELECT failed: ${selectError.message}`);
        
        if (selectData.email === mockData.email && selectData.server_hash === mockData.server_hash) {
            console.log('✅ SELECT verification passed. Data matches.');
        } else {
            console.error('❌ SELECT verification failed. Data mismatch:', selectData);
        }


        // 4. Test DELETE (Cleanup)
        console.log(`\nTesting DELETE operation...`);
        const { error: deleteError } = await supabase
            .from('users')
            .delete()
            .eq('id', insertData.id);

        if (deleteError) throw new Error(`DELETE failed: ${deleteError.message}`);
        console.log('✅ DELETE successful. Cleaned up test data.');

        console.log('\n🎉 ALL DATABASE TESTS PASSED!');
        process.exit(0);

    } catch (err) {
        console.error('\n❌ TEST FAILED');
        console.error('Error:', err.message);
        if (err.code) console.error('Code:', err.code);
        if (err.details) console.error('Details:', err.details);
        process.exit(1);
    }
}

testDatabaseCRUD();
