// hex = "0.4.3"
// serde_json = "1.0.138"


use hex::decode_to_slice;
use serde_json::Value;
use std::fs::OpenOptions;
use std::io::Write;

fn append_data(d:&[u8]) {
    // Open the file in append mode
    let mut file = OpenOptions::new()
        .append(true)
        .open("data1.txt")
        .expect("Unable to open file");

    // Append data to the file
    
    file.write_all(d)
        .expect("Unable to append data");
}

fn get_vecs_keygen() {
    let data: Value = serde_json::from_str(include_str!("../tests/data/keygen.json")).expect("unable to parse data");
    let mut d1 = [0u8;32];
    let mut z = [0u8;32];
    

    let out:[([u8;32],[u8;32],[u8;384*2+32],[u8;768*2+96]);25] = core::array::from_fn(|i|
        {
            let d = &data["testGroups"][0]["tests"][i];
            let mut ek = [0u8;384*2+32];
            let mut dk = [0u8;768*2+96];
            
            let d_str = d["d"].as_str().expect("failed to retrieve data");
            let z_str = d["z"].as_str().expect("failed to retrieve data");
            let ek_str = d["ek"].as_str().expect("failed to retrieve data");
            let dk_str = d["dk"].as_str().expect("failed to retrieve data");

            decode_to_slice(d_str,&mut d1).expect("Decode failure");
            decode_to_slice(z_str,&mut z).expect("Decode failure");
            decode_to_slice(ek_str,&mut ek).expect("Decode failure");
            decode_to_slice(dk_str,&mut dk).expect("Decode failure");

            (d1,z,ek,dk)
        }
    );
    let d_str = format!("const keygen_512:[([S;32],[u8;32],[u8;384*2+32],[u8;768*2+96]);25] = {:?};",out);
    let d = d_str.as_bytes();
    append_data(&d);
    
    let out:[([u8;32],[u8;32],[u8;384*3+32],[u8;768*3+96]);25] = core::array::from_fn(|i|
        {
            let d = &data["testGroups"][1]["tests"][i];
            let mut ek = [0u8;384*3+32];
            let mut dk = [0u8;768*3+96];
            
            let d_str = d["d"].as_str().expect("failed to retrieve data");
            let z_str = d["z"].as_str().expect("failed to retrieve data");
            let ek_str = d["ek"].as_str().expect("failed to retrieve data");
            let dk_str = d["dk"].as_str().expect("failed to retrieve data");

            decode_to_slice(d_str,&mut d1).expect("Decode failure");
            decode_to_slice(z_str,&mut z).expect("Decode failure");
            decode_to_slice(ek_str,&mut ek).expect("Decode failure");
            decode_to_slice(dk_str,&mut dk).expect("Decode failure");

            (d1,z,ek,dk)
        }
    );
    let d_str = format!("const keygen_768:[([u8;32],[u8;32],[u8;384*3+32],[u8;768*3+96]);25] = {:?};",out);
    let d = d_str.as_bytes();
    append_data(&d);
    
    let out:[([u8;32],[u8;32],[u8;384*4+32],[u8;768*4+96]);25] = core::array::from_fn(|i|
        {
            let d = &data["testGroups"][2]["tests"][i];
            let mut ek = [0u8;384*4+32];
            let mut dk = [0u8;768*4+96];
            
            let d_str = d["d"].as_str().expect("failed to retrieve data");
            let z_str = d["z"].as_str().expect("failed to retrieve data");
            let ek_str = d["ek"].as_str().expect("failed to retrieve data");
            let dk_str = d["dk"].as_str().expect("failed to retrieve data");

            decode_to_slice(d_str,&mut d1).expect("Decode failure");
            decode_to_slice(z_str,&mut z).expect("Decode failure");
            decode_to_slice(ek_str,&mut ek).expect("Decode failure");
            decode_to_slice(dk_str,&mut dk).expect("Decode failure");

            (d1,z,ek,dk)
        }
    );
    
    let d_str = format!("const keygen_1024:[([u8;32],[u8;32],[u8;384*4+32],[u8;768*4+96]);25] = {:?};",out);
    let d = d_str.as_bytes();
    append_data(&d);   
}

fn get_vecs_encaps() {
    let data: Value = serde_json::from_str(include_str!("../tests/data/encaps_decaps.json")).expect("unable to parse data");
    let mut k = [0u8;32];
    let mut m = [0u8;32];
    

    let out:[([u8;384*2+32],[u8;32],[u8;32*(10*2+4)],[u8;32]);25] = core::array::from_fn(|i|
        {
            let d = &data["testGroups"][0]["tests"][i];
            let mut ek = [0u8;384*2+32];
            let mut c = [0u8;32*(10*2+4)];
            
            let c_str = d["c"].as_str().expect("failed to retrieve data");
            let k_str = d["k"].as_str().expect("failed to retrieve data");
            let m_str = d["m"].as_str().expect("failed to retrieve data");
            let ek_str = d["ek"].as_str().expect("failed to retrieve data");

            decode_to_slice(c_str,&mut c).expect("Decode failure");
            decode_to_slice(k_str,&mut k).expect("Decode failure");
            decode_to_slice(ek_str,&mut ek).expect("Decode failure");
            decode_to_slice(m_str,&mut m).expect("Decode failure");

            (ek,m,c,k)
        }
    );
    let d_str = format!("const encaps_512:[([u8;384*2+32],[u8;32],[u8;32*(10*2+4)],[u8;32]);25] = {:?};",out);
    let d = d_str.as_bytes();
    append_data(&d);
    
    let out:[([u8;384*3+32],[u8;32],[u8;32*(10*3+4)],[u8;32]);25] = core::array::from_fn(|i|
        {
            let d = &data["testGroups"][1]["tests"][i];
            let mut ek = [0u8;384*3+32];
            let mut c = [0u8;32*(10*3+4)];
            
            let c_str = d["c"].as_str().expect("failed to retrieve data");
            let k_str = d["k"].as_str().expect("failed to retrieve data");
            let m_str = d["m"].as_str().expect("failed to retrieve data");
            let ek_str = d["ek"].as_str().expect("failed to retrieve data");

            decode_to_slice(c_str,&mut c).expect("Decode failure");
            decode_to_slice(k_str,&mut k).expect("Decode failure");
            decode_to_slice(ek_str,&mut ek).expect("Decode failure");
            decode_to_slice(m_str,&mut m).expect("Decode failure");

            (ek,m,c,k)
        }
    );
    let d_str = format!("const encaps_768:[([u8;384*3+32],[u8;32],[u8;32*(10*3+4)],[u8;32]);25] = {:?};",out);
    let d = d_str.as_bytes();
    append_data(&d);
    
    let out:[([u8;384*4+32],[u8;32],[u8;32*(11*4+5)],[u8;32]);25] = core::array::from_fn(|i|
        {
            let d = &data["testGroups"][2]["tests"][i];
            let mut ek = [0u8;384*4+32];
            let mut c = [0u8;32*(11*4+5)];
            
            let c_str = d["c"].as_str().expect("failed to retrieve data");
            let k_str = d["k"].as_str().expect("failed to retrieve data");
            let m_str = d["m"].as_str().expect("failed to retrieve data");
            let ek_str = d["ek"].as_str().expect("failed to retrieve data");

            decode_to_slice(c_str,&mut c).expect("Decode failure");
            decode_to_slice(k_str,&mut k).expect("Decode failure");
            decode_to_slice(ek_str,&mut ek).expect("Decode failure");
            decode_to_slice(m_str,&mut m).expect("Decode failure");

            (ek,m,c,k)
        }
    );

    let d_str = format!("const encaps_1024:[([u8;384*4+32],[u8;32],[u8;32*(11*4+5)],[u8;32]);25] = {:?};",out);
    let d = d_str.as_bytes();
    append_data(&d);   
}

fn get_vecs_decaps() {
    let data: Value = serde_json::from_str(include_str!("../tests/data/encaps_decaps.json")).expect("unable to parse data");
    let mut k = [0u8;32];
    
    let mut dk = [0u8;768*2+96];
    let dk_str = &data["testGroups"][3]["dk"].as_str().expect("failed to retrieve data");
    decode_to_slice(dk_str,&mut dk).expect("Decode failure");
    let out:[([u8;768*2+96],[u8;32*(10*2+4)],[u8;32]);10] = core::array::from_fn(|i|
        {
            let d = &data["testGroups"][3]["tests"][i];
            
            let mut c = [0u8;32*(10*2+4)];
            
            let c_str = d["c"].as_str().expect("failed to retrieve data");
            let k_str = d["k"].as_str().expect("failed to retrieve data");

            decode_to_slice(c_str,&mut c).expect("Decode failure");
            decode_to_slice(k_str,&mut k).expect("Decode failure");

            (dk,c,k)
        }
    );
    let d_str = format!("const decaps_512:[([u8;768*2+96],[u8;32*(10*2+4)],[u8;32]);10] = {:?};",out);
    let d = d_str.as_bytes();
    append_data(&d);
    
    let mut dk = [0u8;768*3+96];
    let dk_str = &data["testGroups"][4]["dk"].as_str().expect("failed to retrieve data");
    decode_to_slice(dk_str,&mut dk).expect("Decode failure");
    let out:[([u8;768*3+96],[u8;32*(10*3+4)],[u8;32]);10] = core::array::from_fn(|i|
        {
            let d = &data["testGroups"][4]["tests"][i];
            let mut c = [0u8;32*(10*3+4)];
            
            let c_str = d["c"].as_str().expect("failed to retrieve data");
            let k_str = d["k"].as_str().expect("failed to retrieve data");

            decode_to_slice(c_str,&mut c).expect("Decode failure");
            decode_to_slice(k_str,&mut k).expect("Decode failure");

            (dk,c,k)
        }
    );
    let d_str = format!("const decaps_768:[([u8;768*3+96],[u8;32*(10*3+4)],[u8;32]);10] = {:?};",out);
    let d = d_str.as_bytes();
    append_data(&d);
    
    let mut dk = [0u8;768*4+96];
    let dk_str = &data["testGroups"][5]["dk"].as_str().expect("failed to retrieve data");
    decode_to_slice(dk_str,&mut dk).expect("Decode failure");
    let out:[([u8;768*4+96],[u8;32*(11*4+5)],[u8;32]);10] = core::array::from_fn(|i|
        {
            let d = &data["testGroups"][5]["tests"][i];
            let mut c = [0u8;32*(11*4+5)];
            
            let c_str = d["c"].as_str().expect("failed to retrieve data");
            let k_str = d["k"].as_str().expect("failed to retrieve data");

            decode_to_slice(c_str,&mut c).expect("Decode failure");
            decode_to_slice(k_str,&mut k).expect("Decode failure");

            (dk,c,k)
        }
    );

    let d_str = format!("const decaps_1024:[([u8;768*4+96],[u8;32*(11*4+5)],[u8;32]);10] = {:?};",out);
    let d = d_str.as_bytes();
    append_data(&d);   
}