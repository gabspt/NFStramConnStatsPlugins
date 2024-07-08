import time
import csv
import logging
from nfstream import NFStreamer, NFPlugin

# Configuración del logger
logging.basicConfig(
    filename='flow_analysis_500.log',  # Nombre del archivo de log
    level=logging.DEBUG,           # Nivel de log (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',  # Formato del log
    datefmt='%Y-%m-%d %H:%M:%S'    # Formato de la fecha en los logs
)
logger = logging.getLogger(__name__)

# Definición del plugin para generar estadísticas
class ConnStatsTimePlugin(NFPlugin):
    def __init__(self, csv_file, time_threshold):
        self.csv_file = csv_file
        self.time_threshold = time_threshold
        self.global_packet_count = 0
        self.flows = {}
        self.start_time = time.time()
        self.last_report_time = self.start_time
        # Crear el archivo CSV y escribir el encabezado
        with open(self.csv_file, 'w', newline='') as csvfile:
            csvwriter = csv.writer(csvfile)
            csvwriter.writerow([
                'Elapsed Time (s)',
                'Flow ID Personalizado',
                'Packets Src to Dst',
                'Bytes Src to Dst',
                'Packets Dst to Src',
                'Bytes Dst to Src',
                'Duration (s)',
                'In PPS',
                'Out PPS',
                'In BPP',
                'Out BPP',
                'In/Out B',
                'In/Out P'
            ])

    def on_init(self, packet, flow):
        # solo TCP o UDP
        if flow.protocol != 6 and flow.protocol != 17:
            return
        
        # Actualizar contador global de paquetes
        self.global_packet_count += 1

        if flow.protocol == 6:
            if not (packet.syn and not packet.ack):
                return

        # creacion de flow id personalizado
        flow.udps.id_personalizado = f"{flow.protocol}-{flow.src_ip}:{flow.src_port} {flow.dst_ip}:{flow.dst_port}"

        current_time = time.time()

        flow.udps.start_time = current_time
        flow.udps.last_seen_time = flow.udps.start_time

        #parametros para indentificar el fin de conexion TCP, luego de 2 FIN y 2 ACK recibidas
        flow.udps.fin_counter = 0
        flow.udps.ack_counter = 0
        flow.udps.flow_closed = 0

        # Guardar el flujo en el plugin
        self.flows[flow.udps.id_personalizado] = flow

        logger.debug(f"Flow {flow.udps.id_personalizado} initialized.")

        # Comprobar si se debe imprimir estadísticas
        if current_time - self.last_report_time >= self.time_threshold:
            self.report_all_flows_stats(current_time)

    def on_update(self, packet, flow):
        if flow.protocol != 6 and flow.protocol != 17:
            return
        
        # Actualizar contador global de paquetes
        self.global_packet_count += 1
        logger.info(f"Packets processed: {self.global_packet_count}")
        
        if flow.protocol == 6:
            id_test = f"{flow.protocol}-{flow.src_ip}:{flow.src_port} {flow.dst_ip}:{flow.dst_port}"
            if id_test not in self.flows:
                return

        current_time = time.time()
        flow.udps.last_seen_time = current_time

        if packet.fin == True and packet.ack == True:
            flow.udps.fin_counter += 1
        if flow.udps.fin_counter >= 1 and packet.ack == True and packet.fin == False and packet.syn == False and packet.rst== False:
            flow.udps.ack_counter += 1
        #check if TCP flow ended -> 2Fin and 2ACK or RST 
        if flow.udps.fin_counter >= 2 and flow.udps.ack_counter>=2 and packet.ack == True and packet.fin == False and packet.syn == False and packet.rst== False:
            flow.udps.flow_closed = 1
            flow.expiration_id = -1
            #logger.debug(f"Flow {flow.udps.id_personalizado} ended normally")
        elif packet.rst == True:
            flow.udps.flow_closed = 2
            flow.expiration_id = -1
            #logger.debug(f"Flow {flow.udps.id_personalizado} ended anormally")
        else:
            # Flujo aun abierto -> Guardar el flujo en el plugin
            self.flows[flow.udps.id_personalizado] = flow

        

        # Comprobar si se debe imprimir estadísticas
        if current_time - self.last_report_time >= self.time_threshold:
            self.report_all_flows_stats(current_time)

    def on_expire(self, flow):
        if flow.protocol != 6 and flow.protocol != 17:
            return
        
        id_test = f"{flow.protocol}-{flow.src_ip}:{flow.src_port} {flow.dst_ip}:{flow.dst_port}"
        if flow.protocol == 6:     
            if id_test not in self.flows:
                return
            
        if id_test in self.flows:
            if flow.udps.flow_closed == 1:
                del self.flows[id_test]
                #logger.debug(f"Flow {id_test} ended normally has been removed from self.flows ")
            elif flow.udps.flow_closed == 2:
                del self.flows[id_test]
                #logger.debug(f"Flow {id_test} ended anormally has been removed from self.flows ")
            else:
                del self.flows[id_test]
                #logger.debug(f"Flow {id_test} expired because {flow.expiration_id} ")


    def report_all_flows_stats(self, report_time):
        #flow_ids = ', '.join(self.flows.keys())
        #logger.info(f"Total active flows: {len(self.flows)} - Flow IDs: {flow_ids}")
        #logger.info(f"Packets processed: {self.global_packet_count}")
        # Resetear el tiempo del último reporte
        self.last_report_time = report_time

        with open(self.csv_file, 'a', newline='') as csvfile:
            csvwriter = csv.writer(csvfile)
            for flow_id, flow in self.flows.items():
                duration = flow.udps.last_seen_time - flow.udps.start_time

                # nuevos features
                if flow.bidirectional_duration_ms > 0:
                    inpps = flow.dst2src_packets / duration
                    outpps = flow.src2dst_packets / duration
                    # inpps = (flow.dst2src_packets / flow.bidirectional_duration_ms)*1000
                    # outpps = (flow.src2dst_packets / flow.bidirectional_duration_ms)*1000
                else:
                    inpps = 0
                    outpps = 0

                if flow.dst2src_packets > 0:
                    inbpp = flow.dst2src_bytes / flow.dst2src_packets
                else:
                    inbpp = 0

                if flow.src2dst_packets > 0:
                    outbpp = flow.src2dst_bytes / flow.src2dst_packets
                    inpoutp = flow.dst2src_packets / flow.src2dst_packets
                else:
                    outbpp = 0
                    inpoutp = 0

                if flow.src2dst_bytes > 0:
                    inboutb = flow.dst2src_bytes / flow.src2dst_bytes
                else:
                    inboutb = 0

                csvwriter.writerow([
                    report_time,
                    flow_id,
                    # flow.src2dst_packets,
                    # flow.src2dst_bytes,
                    # flow.dst2src_packets,
                    # flow.dst2src_bytes,
                    # duration,
                    # flow.bidirectional_duration_ms,
                    inpps,
                    outpps,
                    inbpp,
                    outbpp,
                    inboutb,
                    inpoutp
                ])

            csvwriter.writerow([""])

        


# Inicialización del plugin con el archivo CSV
csv_file = 'flow_stats_time_500.csv'
time_threshold = 0.5
plugin = ConnStatsTimePlugin(csv_file, time_threshold)

# Configuración del streamer con el plugin
streamer = NFStreamer(source="enp0s8", udps=plugin, n_meters=1, idle_timeout=400)

# Procesamiento de flujos en tiempo real
for flow in streamer:
    pass