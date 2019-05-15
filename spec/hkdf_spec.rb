RSpec.describe Hkdf do
  it "has a version number" do
    expect(Hkdf::VERSION).not_to be nil
  end

  require "ruby_hmac"
  require "hmac-sha1"
  require "hmac-sha2"

  class ::String
    def htb
      [self].pack('H*')
    end

    def bth
      unpack('H*').first
    end
  end

  describe ".hkdf" do
    context "Use openssl" do
      subject { described_class.hkdf(ikm, salt: salt, info: info, length: length, hash: "sha256", hash_len: 32).bth }

      let(:ikm) { "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b".htb }
      let(:salt) { "000102030405060708090a0b0c".htb }
      let(:info) { "f0f1f2f3f4f5f6f7f8f9".htb }
      let(:length) { 42 }

      it { is_expected.to eq "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865" }
    end
  end

  describe "#hkdf" do
    context "SHA-256" do
      subject do
        described_class.new(hash_len: 32).hkdf(ikm, salt: salt, info: info, length: length) do |key, data|
          HMAC::SHA256.new(key).update(data).digest
        end.bth
      end

      describe "Basic test case with SHA-256" do
        let(:ikm) { "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b".htb }
        let(:salt) { "000102030405060708090a0b0c".htb }
        let(:info) { "f0f1f2f3f4f5f6f7f8f9".htb }
        let(:length) { 42 }

        it { is_expected.to eq "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865" }
      end

      describe "Test with SHA-256 and longer inputs/outputs" do
        let(:ikm) do
          "000102030405060708090a0b0c0d0e0f" \
          "101112131415161718191a1b1c1d1e1f" \
          "202122232425262728292a2b2c2d2e2f" \
          "303132333435363738393a3b3c3d3e3f" \
          "404142434445464748494a4b4c4d4e4f".htb
        end
        let(:salt) do
          "606162636465666768696a6b6c6d6e6f" \
          "707172737475767778797a7b7c7d7e7f" \
          "808182838485868788898a8b8c8d8e8f" \
          "909192939495969798999a9b9c9d9e9f" \
          "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf".htb
        end
        let(:info) do
          "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf" \
          "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf" \
          "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf" \
          "e0e1e2e3e4e5e6e7e8e9eaebecedeeef" \
          "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff".htb
        end
        let(:length) { 82 }

        it do
          is_expected.to eq "b11e398dc80327a1c8e7f78c596a4934" \
            "4f012eda2d4efad8a050cc4c19afa97c" \
            "59045a99cac7827271cb41c65e590e09" \
            "da3275600c2f09b8367793a9aca3db71" \
            "cc30c58179ec3e87c14c01d5c1f3434f" \
            "1d87"
        end
      end

      describe "Test with SHA-256 and zero-length salt/info" do
        let(:ikm) { "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b".htb }
        let(:salt) { "".htb }
        let(:info) { "".htb }
        let(:length) { 42 }

        it { is_expected.to eq "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8" }
      end
    end

    context "SHA-1" do
      subject do
        described_class.new(hash_len: 20).hkdf(ikm, salt: salt, info: info, length: length) do |key, data|
          HMAC::SHA1.new(key).update(data).digest
        end.bth
      end

      describe "Basic test case with SHA-1" do
        let(:ikm) { "0b0b0b0b0b0b0b0b0b0b0b".htb }
        let(:salt) { "000102030405060708090a0b0c".htb }
        let(:info) { "f0f1f2f3f4f5f6f7f8f9".htb }
        let(:length) { 42 }

        it { is_expected.to eq "085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896" }
      end

      describe "Test with SHA-1 and longer inputs/outputs" do
        let(:ikm) do
          "000102030405060708090a0b0c0d0e0f" \
          "101112131415161718191a1b1c1d1e1f" \
          "202122232425262728292a2b2c2d2e2f" \
          "303132333435363738393a3b3c3d3e3f" \
          "404142434445464748494a4b4c4d4e4f".htb
        end
        let(:salt) do
          "606162636465666768696a6b6c6d6e6f" \
          "707172737475767778797a7b7c7d7e7f" \
          "808182838485868788898a8b8c8d8e8f" \
          "909192939495969798999a9b9c9d9e9f" \
          "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf".htb
        end
        let(:info) do
          "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf" \
          "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf" \
          "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf" \
          "e0e1e2e3e4e5e6e7e8e9eaebecedeeef" \
          "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff".htb
        end
        let(:length) { 82 }

        it do
          is_expected.to eq "0bd770a74d1160f7c9f12cd5912a06eb" \
            "ff6adcae899d92191fe4305673ba2ffe" \
            "8fa3f1a4e5ad79f3f334b3b202b2173c" \
            "486ea37ce3d397ed034c7f9dfeb15c5e" \
            "927336d0441f4c4300e2cff0d0900b52" \
            "d3b4"
        end
      end

      describe "Test with SHA-1 and zero-length salt/info" do
        let(:ikm) { "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b".htb }
        let(:salt) { "".htb }
        let(:info) { "".htb }
        let(:length) { 42 }

        it { is_expected.to eq "0ac1af7002b3d761d1e55298da9d0506b9ae52057220a306e07b6b87e8df21d0ea00033de03984d34918" }
      end

      describe "Test with SHA-1, salt not provided (defaults to HashLen zero octets), zero-length info" do
        let(:ikm) { "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c".htb }
        let(:salt) { nil }
        let(:info) { "".htb }
        let(:length) { 42 }

        it { is_expected.to eq "2c91117204d745f3500d636a62f64f0ab3bae548aa53d423b0d1f27ebba6f5e5673a081d70cce7acfc48" }
      end
    end
  end
end
