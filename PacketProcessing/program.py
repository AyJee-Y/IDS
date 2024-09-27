import queue
from threading import Thread, Event
from scapy.all import sniff, IP, TCP, UDP, Raw
from concurrent.futures import ThreadPoolExecutor
import time

from payloadSignature import SignaturesBasedDetection_Payloads

# Shared queue for packet processing
packet_queue = queue.Queue(maxsize=1000)  # Adjust maxsize as needed

# Event to signal threads to stop
stop_event = Event()

def packet_sniffer(packet_queue):
    def packet_callback(packet):
        if IP in packet:
            packet_queue.put(packet)
    
    sniff(prn=packet_callback, store=0, stop_filter=lambda x: stop_event.is_set())

def packet_processor(packet_queue, analyzer_functions):
    with ThreadPoolExecutor(max_workers=len(analyzer_functions)) as executor:
        while not stop_event.is_set():
            try:
                packet = packet_queue.get(block=False)
                # Submit all analyzer functions to the thread pool
                futures = [executor.submit(func, packet) for func in analyzer_functions]
                # Wait for all analyzer functions to complete
                for future in futures:
                    future.result()
                packet_queue.task_done()
            except queue.Empty:
                time.sleep(0.01)
            except Exception as e:
                print(f'Error processing packet: {e}')

def main():
    analyzer_functions = [SignaturesBasedDetection_Payloads]
    
    # Start the packet sniffer (producer)
    sniffer_thread = Thread(target=packet_sniffer, args=(packet_queue,))
    sniffer_thread.start()

    # Start multiple packet processors (consumers)
    num_processors = 4  # Adjust based on your needs
    processor_threads = []
    for _ in range(num_processors):
        processor_thread = Thread(target=packet_processor, args=(packet_queue, analyzer_functions))
        processor_thread.start()
        processor_threads.append(processor_thread)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Stopping IDS...")
        stop_event.set()

    # Wait for all processors to finish
    for thread in processor_threads:
        thread.join()

    sniffer_thread.join()

if __name__ == "__main__":
    main()