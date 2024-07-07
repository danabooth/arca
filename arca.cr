require "openssl"
require "digest"

# arca ecnryption engine
# ARGV[0] : input file
# ARGV[1] : output file
# ARGV[2] : 256 bit keystream (128 bit for sm4)
# ARGV[3] : 128 bit iv
# ARGV[4] : "e" to encrypt, "d" to decrypt
# ARGV[5] : cipher to use, aes, aria, camellia, sm4, or chacha20
# ARGV[6] : mode, cbc, cfb, ctr, ofb

version = "0.11a"

def encrypt_file(original_file, destination_file, key, iv, ed, r, mode, iter)
    r = r.downcase()
    infile = File.open(original_file, "rb")
    outfile = File.open(destination_file, "wb")
    infile_size = infile.size

    if r == "camellia"
        mcipher = "camellia-256-"
    elsif r == "aria"
        mcipher = "aria-256-"
    elsif r == "aes"
        mcipher = "aes-256-"
    elsif r == "sm4"
        mcipher = "sm4-"
    elsif r == "chacha20"
        mcipher = "chacha20"
    else
        print("#{r} is not a supported cipher\n")
        exit(1)
    end

    if mode == "cbc" && mcipher != "chacha20"
        cipher = OpenSSL::Cipher.new(mcipher + "cbc")
    elsif mode == "cfb" && mcipher != "chacha20"
        cipher = OpenSSL::Cipher.new(mcipher + "cfb")
    elsif mode == "ctr" && mcipher != "chacha20"
        cipher = OpenSSL::Cipher.new(mcipher + "ctr")
    elsif mode == "ofb" && mcipher != "chacha20"
        cipher = OpenSSL::Cipher.new(mcipher + "ofb")
    elsif mcipher == "chacha20"
        cipher = OpenSSL::Cipher.new("chacha20")
    else
        print("#{mode} is not a supported mode\n")
        exit(1)
    end

    if ed == "e"
        cipher.encrypt
    elsif ed == "d"
        cipher.decrypt
    else
        print("error")
        exit(1)
    end
    cipher.key = key
    cipher.iv = iv

    if infile_size <= 16384
        read_length = infile_size
    else
        read_length = 16384
    end
	while infile_size > 0
		buf = infile.read_string(read_length)
        st = cipher.update(buf)
		outfile.write(st)
        infile_size -= read_length
		if infile_size <= 16384
			read_length = infile_size
		end
	end
    st = cipher.final
    outfile.write(st)

    outfile.close
    infile.close
end

def main(a, b, c, d, e, f, g, h)
    h = h.to_i
    c = Digest::SHA256.digest c
	counter = 0
	while counter < h
        c = Digest::SHA512.digest c
		c = Digest::SHA256.digest c
		counter += 2
	end
    d = (Digest::SHA256.digest d)[0..15]
    encrypt_file(a, b, c, d, e, f, g, h)
end

if ARGV.size != 8
    print("arca encryption engine version #{version}\n")
    print("usage: arca <input_filename> <output_filename> password IV <\"e\" encrypts, \"d\" decrypts>, <aes, aria, or camellia> <mode \(cbc, cfb, ctr, ofb\)> iterations\n")
	exit(3)
end
if File.file?(ARGV[0]) != true
    print("#{ARGV[0]} is not a file")
    exit(2)
end

 main(ARGV[0], ARGV[1], ARGV[2], ARGV[3], ARGV[4], ARGV[5], ARGV[6], ARGV[7])
