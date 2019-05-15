require "openssl"

class Hkdf
  VERSION = "0.1.0"

  def initialize(hash_len: 32)
    @hash_len = hash_len
  end

  def hkdf(ikm, salt: nil, info: '', length: 0, &block)
    salt = salt || "\00" * @hash_len
    prk = extract(salt, ikm, &block)
    expand(prk, info, length, &block)
  end

  private

  def extract(salt, ikm, &block)
    hmac_hash(salt, ikm, &block)
  end

  def expand(prk, info, length, &block)
    n = (length.to_f/@hash_len).ceil
    t = (1..n).inject([]) do |t, i|
      input = (t.last || '') + info + i.chr
      t << hmac_hash(prk, input, &block)
      t
    end
    t.join[0...length]
  end

  def hmac_hash(key, data, &block)
    block.call(key, data)
  end

  class << self
    def hkdf(ikm, salt: nil, info: '', length: 0, hash: nil, hash_len: 32, &block)
      salt = salt || "\00" * hash_len
      if openssl?(hash)
        OpenSSL::KDF.hkdf(ikm, hash: hash, salt: salt, info: info, length: length)
      elsif block
        me = Hkdf.new(hash_len: hash_len)
        me.hkdf(ikm, salt: salt, info: info, length: length, &block)
      else
        raise ArgumentError, "hash algolithm is not supported and/or hkdf is not supported in openssl"
      end
    end

    private

    def openssl?(hash)
      return false unless OpenSSL::KDF.respond_to?(:hkdf)
      return true if hash.is_a?(OpenSSL::Digest)
      return true if hash.is_a?(String) && OpenSSL::Digest.constants.include?(hash.upcase.to_sym)
      false
    end
  end
end
