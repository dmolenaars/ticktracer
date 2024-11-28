import argparse
import asyncio
import ccxt.pro as ccxt
import concurrent.futures
import multiprocessing
import numpy as np
import os
import platform
import pyshark
import sslkeylog
import tqdm

from parser import get_parser
from prettytable import PrettyTable
from time import sleep
from typing import List

SSLKEYLOGFILE_FILE = "secrets.log"
SSLKEYLOGFILE_PATH = os.path.abspath(SSLKEYLOGFILE_FILE)


def print_report(latency_data) -> None:
    """
    Prints a detailed report of latency data including percentiles and total samples.

    :param latency_data: List of latency values in milliseconds.
    """
    matrix_table = PrettyTable(["Percentile", "Latency in milliseconds"])
    if len(latency_data) > 0:
        matrix_table.add_rows(
            [
                ["MIN", round(np.min(latency_data), 3)],
                ["25%", round(np.percentile(latency_data, 25), 3)],
                ["50%", round(np.percentile(latency_data, 50), 3)],
                ["75%", round(np.percentile(latency_data, 75), 3)],
                ["90%", round(np.percentile(latency_data, 90), 3)],
                ["95%", round(np.percentile(latency_data, 95), 3)],
                ["99%", round(np.percentile(latency_data, 99), 3)],
                ["99.9%", round(np.percentile(latency_data, 99.9), 3)],
                ["MAX", round(np.max(latency_data), 3)],
            ]
        )
    else:
        matrix_table.add_rows(
            [
                ["MIN", "-"],
                ["25%", "-"],
                ["50%", "-"],
                ["75%", "-"],
                ["90%", "-"],
                ["95%", "-"],
                ["99%", "-"],
                ["99.9%", "-"],
                ["MAX", "-"],
            ]
        )
    print(f"Total samples taken: {len(latency_data)}")
    print("Latency report:")
    print(f"\n{matrix_table}")


def get_latency(packet: pyshark.packet.packet.Packet, parser) -> float | None:
    """
    Extracts and calculates the latency from a WebSocket packet.

    :param packet: A PyShark packet object.
    :param parser: An initialized exchange parser that can extract the contents from the exchange-specific payload.
    :return: The latency in milliseconds or None if the packet does not contain the required information.
    """
    if "WEBSOCKET" in packet:
        try:
            ws_packet = packet["WEBSOCKET"]
            ws_payload = ws_packet.get("websocket.payload")
            if ws_payload is not None:
                text_payload = ws_payload.get(
                    "websocket.payload.text"
                ).get_default_value()
                ts = parser.parse_timestamp(text_payload)
                if ts is not None:
                    latency = (float(packet.frame_info.time_epoch) * 1000) - ts
                    return latency
        except ValueError as e:
            pass


def capture_packets(duration: int, exchange_id: str, interface: str) -> List[float]:
    """
    Captures packets from a network interface and extracts latency data.

    :param duration: Duration in seconds to capture packets.
    :param interface: The network interface to monitor. Usually eth0 or en0.
    :param exchange_id: The id of the exchange to connect to.
    :return: A list of latency values in milliseconds.
    """
    latency_samples = []
    parser_class = get_parser(exchange_id)
    exchange_parser = parser_class()
    capture = pyshark.LiveCapture(
        interface=interface,
        custom_parameters=["-a", f"duration:{duration}"],
        use_json=True,
        override_prefs={
            "tls.keylog_file": SSLKEYLOGFILE_PATH,
            "tls.desegment_ssl_records": "TRUE",
            "tls.desegment_ssl_application_data": "TRUE",
            "tcp.desegment_tcp_streams": "TRUE",
        },
        bpf_filter=f"tcp port {exchange_parser.port}",
    )
    for packet in capture.sniff_continuously():
        latency = get_latency(packet, exchange_parser)
        if latency is not None:
            latency_samples.append(latency)
    return latency_samples


def monitor(
    run: multiprocessing.Event, duration: int, exchange_id: str, interface: str
) -> List[float]:
    """
    Monitors network traffic and captures latency data.

    :param run: A multiprocessing Event to control the monitoring process.
    :param duration: Duration in seconds to monitor.
    :param interface: The network interface to monitor. Usually eth0 or en0.
    :param exchange_id: The id of the exchange to connect to.
    :return: A list of latency values in milliseconds.
    """
    while run.is_set():
        latency_samples = capture_packets(duration, exchange_id, interface)
        run.clear()
    return latency_samples


async def start_feed(run: multiprocessing.Event, pair: str, exchange_id: str) -> None:
    """
    Starts a WebSocket feed to an exchange to simulate traffic.

    :param run: A multiprocessing Event to control the feed process.
    :param pair: The trading pair for which to start a websocket feed.
    :param exchange_id: The id of the exchange to connect to.
    """
    exchange_class = getattr(ccxt, exchange_id)
    exchange = exchange_class()
    try:
        while run.is_set():
            await exchange.watch_tickers([pair])
    except BaseException as b:
        print(b)
        pass
    finally:
        await exchange.close()


def feed(run: multiprocessing.Event, pair: str, exchange_id: str) -> None:
    """
    Runs the start_feed coroutine in an asyncio event loop.

    :param run: A multiprocessing Event to control the feed process.
    :param pair: The trading pair for which to start a websocket feed.
    :param exchange_id: The id of the exchange to connect to.

    """
    asyncio.run(start_feed(run, pair, exchange_id))


def loading_bar(run, duration) -> None:
    """
    Displays a loading bar during the monitoring process.

    :param duration: Duration in seconds to display the loading bar.
    """
    print("Starting latency monitoring (Press CTRL+C to stop)...")
    for i in tqdm.trange(duration):
        if not run.is_set():
            break
        sleep(1)
    print("Exiting...")


def main():
    try:
        system = platform.system()
        parser = argparse.ArgumentParser("ticktracer")
        parser.add_argument(
            "-e",
            "--exchange_id",
            help="The exchange to connect with.",
            type=str,
            choices=["okx", "binance", "bybit"],
            required=True,
        )
        parser.add_argument(
            "-p",
            "--pair",
            help="The trading pair to monitor. Look up the specific format on the exchange's API documentation",
            type=str,
            required=True,
        )
        parser.add_argument(
            "-d",
            "--duration",
            help="Duration in seconds to monitor.",
            type=int,
            required=True,
        )
        parser.add_argument(
            "-i",
            "--interface",
            help="The network interface to listen on. Default is eth0 for Linux or en0 for macOS.",
            default=("eth0" if system == "Linux" else "en0"),
            type=str,
        )
        args = parser.parse_args()

        # Initialize TLS secrets file for Pyshark decryption.
        sslkeylog.set_keylog(SSLKEYLOGFILE_PATH)

        # Initialize control event.
        manager = multiprocessing.Manager()
        run = manager.Event()
        run.set()

        # Initialize process pool.
        pool = concurrent.futures.ThreadPoolExecutor()
        monitor_process = pool.submit(
            monitor,
            run,
            args.duration,
            args.exchange_id,
            args.interface,
        )
        feed_process = pool.submit(feed, run, args.pair, args.exchange_id)
        load_process = pool.submit(loading_bar, run, args.duration)

        # Print results.
        latency_samples = [] if (result := monitor_process.result()) is None else result
        print_report(latency_samples)
    except KeyboardInterrupt:
        run.clear()
        pool.shutdown()


if __name__ == "__main__":
    main()
