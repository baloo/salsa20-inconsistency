use hex_literal::hex;

fn main() {
    println!("Hello, world!");
}

fn scrypt_block_mix_orig(input: &[u8], output: &mut [u8]) {
    use salsa20orig::{
        cipher::{typenum::U4, StreamCipherCore},
        SalsaCore,
    };

    type Salsa20_8 = SalsaCore<U4>;

    let mut x = [0u8; 64];
    x.copy_from_slice(&input[input.len() - 64..]);

    let mut t = [0u8; 64];

    for (i, chunk) in input.chunks(64).enumerate() {
        xor(&x, chunk, &mut t);

        let mut t2 = [0u32; 16];

        for (c, b) in t.chunks_exact(4).zip(t2.iter_mut()) {
            *b = u32::from_le_bytes(c.try_into().unwrap());
        }

        Salsa20_8::from_raw_state(t2).write_keystream_block((&mut x).into());

        let pos = if i % 2 == 0 {
            (i / 2) * 64
        } else {
            (i / 2) * 64 + input.len() / 2
        };

        output[pos..pos + 64].copy_from_slice(&x);
    }
}

fn scrypt_block_mix_new(input: &[u8], output: &mut [u8]) {
    use salsa20::{
        cipher::{typenum::U4, StreamCipherCore},
        SalsaCore,
    };

    type Salsa20_8 = SalsaCore<U4>;

    let mut x = [0u8; 64];
    x.copy_from_slice(&input[input.len() - 64..]);

    let mut t = [0u8; 64];

    for (i, chunk) in input.chunks(64).enumerate() {
        xor(&x, chunk, &mut t);

        let mut t2 = [0u32; 16];

        for (c, b) in t.chunks_exact(4).zip(t2.iter_mut()) {
            *b = u32::from_le_bytes(c.try_into().unwrap());
        }

        Salsa20_8::from_raw_state(t2).write_keystream_block((&mut x).into());

        let pos = if i % 2 == 0 {
            (i / 2) * 64
        } else {
            (i / 2) * 64 + input.len() / 2
        };

        output[pos..pos + 64].copy_from_slice(&x);
    }
}

fn xor(x: &[u8], y: &[u8], output: &mut [u8]) {
    for ((out, &x_i), &y_i) in output.iter_mut().zip(x.iter()).zip(y.iter()) {
        *out = x_i ^ y_i;
    }
}

#[test]
fn test_regression() {
    let input_orig = SAMPLE.clone();
    let input_new = SAMPLE.clone();

    let mut out_orig = [0; 1024];
    let mut out_new = [0; 1024];

    scrypt_block_mix_orig(&input_orig, &mut out_orig[..]);
    scrypt_block_mix_new(&input_new, &mut out_new[..]);

    assert_eq!(out_orig, out_new);
}

const SAMPLE: [u8;1024] = hex!("acaa1584d33a2b9e626333fc5237cbfbe175c29daf4f724f1c22fc21ddcfecb8e0f072ae7e26b4526e0dd18eb9274799531c633227674ecd32ceb61187dcab298052a85500cdc051d3076c92dcb08d712c1ea69036ba22498f56df9b7fa562001a09d967aa3c5bedbd2b43768cf0b92c8404712227430c2a2bdb43989f20147232ebd5315f556320a8b49c15f6350c3ec6c8f66dc7b40fabbaf11feee9e6216d0e47469f696e54afad07b14fb1bc006836e64326a13b76a7fc24f2781db8ecc6a422cd7f8b7dc1b355e6e26b962fdc6358ab03011095ebc618c9bc77f39f9c9ac2199cccb9a2ff9e253f0f5569e41fa47dfe908db46d9e05d4db3502b845bfa56853cd5f86e21b902386d9f29f06abad99ad4a1615a64fa6a1dfff7abe0c3d6f9a403046c11d325634c639ec0eadd68aa4f1628ca7d5d372fa112456563d40f9f78f5ae7b54f9c60dee5191dd5ba1117eca90c0ce1c3d72069e9290f6efbe70bca6d5ad7a11ba729e5ad739e2c129806c4b08988456a3bdb0b485219bf55599fd8f2892e5bb2f84f9f4fe0833a4b7d83b9dc1e9ed568f03e80d12894271ad876efd9fc2ecbf45b7263b901f62e240b85f8919da22bea4aff10997d1c8ad1f3cacd237281d41708d05214afa9db2680ba496e758b165d2be4fddbe4563e804e3daeb1a981906debe608421edcf5253fb08d24dc2f740746fccecc7b34d37bf674a6436dc4b4088c1bb21d8c7b42beb22dd3d4e688708a99cca2cd8c0ab0e4c4ddcaa9940a1153b032869d990204d27d40007c975ab439cd277cca3995c0b90480962828f016a5ee180598822328cab8d45ba90604a0d05536ac3e475aafe6b22b617964305c2ec925848314a4042fd53a2c13ee6d5e58600211180cbf40dec436d6d59cdc8c73795ce79fca8ef092439945c61999e5cdbac1bd179b2d4023964bc26fc5551b6120e1f32a92f41a62594c4806e88ba0c960995a78faed8b221223d560f41d215e4b0dfc937fd2d2c7823e8f132296ab9064b7a723a740bbca8bb67903e8df00f2c5a33a0f6d07ccf5e494830a453756d005b5a1ef8cbf49122587c08b7c0386a7ebf66d46d02b079dfb04422bfe6889ad1536c0363646794fc98743567c66f8621f72e514547b22ffdd5b0995b136896f1c08f3b3a5a81e636e6dd0a0587dbf6c94ea9a327abd458085963f857647f317143d6cd9b915ce817403a39b0be08503e21928e875f6dc952b959dfbe921a57438b4a2a1a6a951ad405414658813a4da46d04a00722d3387b308addc054048d0084acbd53ca3b2a383cc7c36408cfce7082eb2ba2a9e0e1c3cbeb46e02a7c1ec3d5aece79ded31d6e27b8dcf83fa131d44aaa4241dc58a86d0851d5cb1815e05cc0b8da1f4a39b2ef6a5db2f2bec267136a57a78930da84da1e1984baeb30aca20642c4da8a4cb42fb4f");
