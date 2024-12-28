#include "hookapi.h"

#define DONE(x) accept(SBUF(x), __LINE__)
#define NOPE(x) rollback(SBUF(x), __LINE__)

#define SECONDS_IN_WEEK 604800
#define MIN_BALANCE 15000000  // 15 XAH in drops
#define TOP_UP_AMOUNT 15000000 // 15 XAH in drops

uint8_t txn[229] = {
    /* Transaction template similar to what was provided earlier */
    0x12U, 0x00U, 0x63U,  // tt = Invoke
    0x22U, 0x00U, 0x00U, 0x00U, 0x00U,  // flags
    0x24U, 0x00U, 0x00U, 0x00U, 0x00U,  // sequence
    0x20U, 0x1AU, 0x00U, 0x00U, 0x00U, 0x00U, // firstledgersequence
    0x20U, 0x1BU, 0x00U, 0x00U, 0x00U, 0x00U, // lastledgersequence
    0x68U, 0x40U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, // fee
    0x73U, 0x21U, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, // signingpubkey
    0x81U, 0x14U, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, // account
    0x83U, 0x14U, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, // destination
    // 116 bytes for emit details, left uninitialized here for simplicity
};

#define FLS_OUT (txn + 15U) 
#define LLS_OUT (txn + 21U) 
#define FEE_OUT (txn + 26U) 
#define ACCOUNT_OUT (txn + 71U) 
#define DEST_OUT (txn + 93U) 
#define EMIT_OUT (txn + 113U) 

// Sample host accounts
uint8_t HOST_ACCOUNTS[5][20] = {
    {0x72, 0x61, 0x45, 0x66, 0x72, 0x79, 0x35, 0x59, 0x59, 0x51, 0x54, 0x58, 0x6d, 0x71, 0x50, 0x53, 0x4c, 0x35, 0x64, 0x52},
    {0x72, 0x50, 0x46, 0x47, 0x5a, 0x69, 0x57, 0x41, 0x6d, 0x4c, 0x5a, 0x71, 0x43, 0x54, 0x41, 0x45, 0x75, 0x45, 0x71, 0x73},
    {0x72, 0x44, 0x73, 0x56, 0x6b, 0x36, 0x71, 0x31, 0x79, 0x43, 0x59, 0x72, 0x74, 0x4e, 0x35, 0x62, 0x61, 0x42, 0x6f, 0x6d},
    {0x72, 0x51, 0x4c, 0x62, 0x48, 0x61, 0x6d, 0x7a, 0x42, 0x64, 0x48, 0x68, 0x5a, 0x34, 0x6f, 0x34, 0x69, 0x34, 0x66, 0x62},
    {0x72, 0x48, 0x74, 0x46, 0x4c, 0x50, 0x57, 0x31, 0x32, 0x76, 0x65, 0x6b, 0x61, 0x67, 0x6d, 0x6b, 0x77, 0x51, 0x52, 0x32}
};

int64_t hook(uint32_t reserved) {
    uint32_t current_time = ledger_timestamp();
    static uint32_t last_check_time = 0;  // This might not persist across hook executions, adjust if possible
    
    if (current_time - last_check_time >= SECONDS_IN_WEEK) {
        last_check_time = current_time;
        
        hook_account(ACCOUNT_OUT, 20);  // Funding account

        for (int i = 0; i < 5; i++) {
            uint8_t keylet[34];
            if (util_keylet(SBUF(keylet), KEYLET_ACCOUNT, HOST_ACCOUNTS[i], 20, 0, 0, 0, 0) != 34)
                NOPE("Topup: Fetching Keylet Failed for host account.");

            slot_set(SBUF(keylet), i + 1);
            slot_subfield(i + 1, sfBalance, 1);
            int64_t balance = slot_float(i + 1);

            if (float_compare(balance, MIN_BALANCE, COMPARE_LESS) == 1) {
                etxn_reserve(1);
                uint32_t current_ledger = ledger_seq();
                uint32_t fls = current_ledger + 1;
                uint32_t lls = fls + 4;
                *((uint32_t *)(FLS_OUT)) = FLIP_ENDIAN(fls);
                *((uint32_t *)(LLS_OUT)) = FLIP_ENDIAN(lls);

                // Set destination for payment
                memcpy(DEST_OUT, HOST_ACCOUNTS[i], 20);

                // Set payment amount
                uint8_t amount[8];
                amount[0] = 0b01000000 + ((TOP_UP_AMOUNT >> 56) & 0b00111111);
                for (int j = 1; j < 8; j++) {
                    amount[j] = (TOP_UP_AMOUNT >> (56 - 8*j)) & 0xFFU;
                }
                memcpy(EMIT_OUT + 4, amount, 8);

                etxn_details(EMIT_OUT, 116U);
                {
                    int64_t fee = etxn_fee_base(SBUF(txn));
                    uint8_t *b = FEE_OUT;
                    *b++ = 0b01000000 + ((fee >> 56) & 0b00111111);
                    for (int j = 1; j < 8; j++) {
                        *b++ = (fee >> (56 - 8*j)) & 0xFFU;
                    }
                }
                
                uint8_t emithash[32];  
                if (emit(SBUF(emithash), SBUF(txn)) != 32)
                    NOPE("Topup: Failed To Emit.");
            }
        }
        DONE("Topup: Weekly check completed.");
    }
    DONE("Topup: Not time for check.");
    return 0;          
}
