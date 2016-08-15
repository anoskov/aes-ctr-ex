defmodule AesCtr.Mixfile do
  use Mix.Project

  def project do
    [app: :aes_ctr,
     version: "0.1.0",
     elixir: "~> 1.3",
     build_embedded: Mix.env == :prod,
     start_permanent: Mix.env == :prod,
     deps: deps(),
     aliases: aliases(),
     description: description(),
     package: package()]
  end

  def application do
    [applications: []]
  end

  defp deps do
    [{:ex_doc, ">= 0.0.0", only: :dev}]
  end

  defp aliases do
    []
  end

  defp description do
    "AES cipher in CTR mode."
  end

  defp package do
    [name: :aes_ctr,
     files: ["lib", "mix.exs"],
     maintainers: ["Andrey Noskov"],
     licenses: ["MIT"],
     links: %{"github" => "https://github.com/anoskov/aes-ctr-ex"}]
  end
end
