defmodule AesCtr do
  @doc """
   Returns an AES key.
   Accepts a `key_format` (`:base64`|`:bytes`) to determine type of key to produce
   and `key_length` (`128`|`192`|`256`).
       iex> {:ok, key} = AesCtr.generate_aes_key(:bytes)
       iex> assert bit_size(key) == 128
       true
       iex> {:ok, key} = AesCtr.generate_aes_key(:bytes, 256)
       iex> assert bit_size(key) == 256
       true
       iex> {:ok, key} = AesCtr.generate_aes_key(:base64)
       iex> assert String.length(key) == 24
       true
  """
  @spec generate_aes_key(atom, non_neg_integer) :: {:ok, binary} | {:error, binary}
  def generate_aes_key(format, length \\ 128)
  def generate_aes_key(:base64, length) do
    {:ok, bytes} = rand_bytes(round(length / 8))
    url_encode64(bytes)
  end
  def generate_aes_key(:bytes, length) do
    rand_bytes(round(length / 8))
  end
  def generate_aes_key(_, _) do
    {:error, "invalid key_format"}
  end

  @doc """
    Encrypt a `binary` with AES in CTR mode.
      iex> clear_text = "my-clear-text"
      iex> {:ok, aes_128_key} = AesCtr.generate_aes_key(:bytes)
      iex> {:ok, cipher} = AesCtr.encrypt(clear_text, aes_128_key)
      iex> assert(is_bitstring(cipher_text))
      true
  """
  @spec encrypt(String.t, String.t) :: {atom, binary}
  def encrypt(text, key) do
    {:ok, iv} = rand_bytes(16)
    state = :crypto.stream_init(:aes_ctr, key, iv)
    {_state, ciphertext} = :crypto.stream_encrypt(state, to_string(text))

    {:ok, iv <> ciphertext}
  end

  @doc """
    Returns a clear-text string decrypted with AES in CTR mode.
        iex> clear_text = "my-clear-text"
        iex> {:ok, aes_128_key} = AesCtr.generate_aes_key(:bytes)
        iex> {:ok, cipher} = AesCtr.encrypt(clear_text, aes_128_key)
        iex> {:ok, val} = AesCtr.decrypt(cipher, aes_128_key)
        iex> assert(val == clear_text)
        true
  """
  @spec decrypt(binary, String.t) :: {atom, String.t}
  def decrypt(cipher, key) do
    <<iv::binary-16, ciphertext::binary>> = cipher

    state = :crypto.stream_init(:aes_ctr, key, iv)
    {_state, plaintext} = :crypto.stream_decrypt(state, ciphertext)

    {:ok, plaintext}
  end


  @doc """
   Returns a string of random where the length is equal to `integer`.
       iex> {:ok, rand_bytes} = AesCtr.rand_bytes(16)
       iex> assert(byte_size(rand_bytes) == 16)
       true
       iex> assert(bit_size(rand_bytes) == 128)
       true

       iex> {:ok, rand_bytes} = AesCtr.rand_bytes(24)
       iex> assert(byte_size(rand_bytes) == 24)
       true
       iex> assert(bit_size(rand_bytes) == 192)
       true
       iex> {:ok, rand_bytes} = AesCtr.rand_bytes(32)
       iex> assert(byte_size(rand_bytes) == 32)
       true
       iex> assert(bit_size(rand_bytes) == 256)
       true
  """
  @spec rand_bytes(integer) :: {:ok, binary}
  def rand_bytes(length) do
    {:ok, :crypto.strong_rand_bytes(length)}
  end

  def url_encode64(bytes_to_encode) do
   {:ok, Base.url_encode64(bytes_to_encode)}
  end
end
