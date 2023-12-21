# ShoVi -IP Lookup Tool 🔍

**ShoVi** is a IP Lookup Tool provides automated threat intelligence lookups for IPs based on your clipboard. It checks the clipboard for IP addresses, then perform lookups using Shodan and VirusTotal APIs to retrieve information.


## Features 🚀

- **GeoLocation:** Show you the country, city if there is. 
- **Hostname:** You can see what hostprovider they are using. 
- **Cloud Provider:** What cloud provider/cloud service its using. 
- **Ports:** Yes, it can show you open ports.
- **Threats:** Suspicous, malicious, harmless, etc., detected from an IP. 

## Usage 🛠️

### Option 1: Exe File

1. Download the [exe file](https://github.com/ananquay15x9/ShoVi/blob/master/shovi.exe) from the releases section.
2. Run the executable to launch the Password Generator and Checker tool.

### Option 2: Python Code

1. Download the [Python code](https://github.com/ananquay15x9/ShoVi/blob/master/sho-vi.py) from this repository.
2. Open the code in your preferred IDE.
3. Customize and modify the code to suit your preferences.
4. Run the code in your IDE.

### Option 3: Git Clone

Alternatively, you can clone the project using Git:

```bash
git clone https://github.com/ananquay15x9/ShoVi.git
cd ShoVi
python sho-vi.py
```
## How to Use 📖

1. **Copy IP:**
    - Copy an IP address to your clipboard (Ctrl + C). 
    - It can be any kind of clipboard, whether it's on your browser or on a notepad.
    - Once a valid IP address is copied, you should see the information of that IP. 

## Note 🚨
 - If you use the exe file downloaded from this repository and it's showing 'null' for IP and Last Analysis Stats.
 - It means that my API usage has reached its limit. Since you're using the executable file, it contains my free VirusTotal API in it.
 - You can download and run this [Python code](https://github.com/ananquay15x9/ShoVi/blob/master/sho-vi.py) with your own API keys.
 - You will need to go to [VirusTotal official website](https://www.virustotal.com/gui/home/upload) and [Shodan offical website](https://www.shodan.io) to register and obtain an API key.
 - They are free!
   
## Contributing 🤝

Contributions are welcome! Feel free to open issues, suggest enhancements, or submit pull requests to improve the project.

## License 📝

This project is licensed under the [MIT License](LICENSE).

---

**ShoVi** - Explore IP all over the world! 🌐
