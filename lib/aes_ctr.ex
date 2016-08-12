defmodule AesCtr do
    @doc """
   Returns an AES key.
   Accepts a `key_format` (`:base64`|`:bytes`) to determine type of key to produce.
   ## Examples
       iex> {:ok, key} = AesCtr.generate_aes_key(:aes_128, :bytes)
       iex> assert bit_size(key) == 128
       true
       iex> {:ok, key} = AesCtr.generate_aes_key(:aes_128, :base64)
       iex> assert String.length(key) == 24
       true
  """
  @spec generate_aes_key(atom) :: {:ok, binary} | {:error, binary}
  def generate_aes_key(:base64) do
    {:ok, bytes} = rand_bytes(16)
    url_encode64(bytes)
  end
  def generate_aes_key(:bytes) do
    rand_bytes(16)
  end
  def generate_aes_key(_) do
    {:error, "invalid key_format"}
  end

    @doc """
   Returns a string of random where the length is equal to `integer`.
   ## Examples
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
