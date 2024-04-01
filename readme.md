# Wick Shield - Advanced Network Monitor with IP Blocking

Wick Shield is an advanced network monitoring tool developed in Python. It provides real-time monitoring of network traffic, particularly focusing on ICMP packets. Additionally, it offers the capability to block suspicious IP addresses automatically.

![Wick Shield Preview](https://media.discordapp.net/attachments/1216088448004526193/1224321404007350354/image.png?ex=661d1129&is=660a9c29&hm=76310c293cf698bba947e571f1af3875cc33cfa1f125a782ed0e3bb520493ea4&=&format=webp&quality=lossless&width=1200&height=667)

## Features

- Real-time monitoring of network traffic.
- Detection of suspicious IP addresses based on configurable thresholds.
- Automatic blocking of suspicious IP addresses.
- Fetching details of IP addresses from external sources.
- Visual representation of network traffic through graphs.

## Dependencies

- Python 3.x
- scapy
- matplotlib
- requests

## Installation

To install Wick Shield and its dependencies, follow these steps :

1. Clone this repository or download the source code.

2. Navigate to the project directory.

3. Run the `install.bat` file to install the required Python packages. Alternatively, you can manually install the dependencies using pip :

    ```
    pip install scapy matplotlib requests
    ```

## Usage

To start Wick Shield, follow these steps :

1. Ensure that the dependencies are installed (see Installation section).

2. Run the `start.bat` file. This will execute the Wick Shield tool.

3. The Wick Shield GUI will open, displaying two tabs: "Network Traffic" and "Logs". The tool will start monitoring network traffic in real-time.

4. The "Network Traffic" tab shows a graph representing the network traffic from various IP addresses.

5. The "Logs" tab displays real-time logs of network activity and actions taken by the tool.

6. To fetch details of an IP address manually:
    - Click on the "Fetch IP Details" button.
    - Enter the IP address when prompted.
    - Details of the IP address will be displayed in a dialog box.

7. To close the Wick Shield tool, simply close the GUI window. The tool will stop monitoring and exit gracefully.

## Contributing

Contributions to Wick Shield are welcome! If you find any issues or have suggestions for improvements, please feel free to open an issue or submit a pull request.

## License

This project is licensed under the [MIT License](LICENSE).

## Acknowledgments

- Special thanks to the developers of the libraries used in this project: scapy, matplotlib, and requests.

## Contact

- Email : wick@wick-studio.com

- Website : https://wickdev.xyz

- Discord : https://discord.gg/wicks

- Youtube : https://www.youtube.com/@wick_studio