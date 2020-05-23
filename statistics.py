

class Statisitics:
    def __init__(self):
        self.clients = {}

    def update(self, client_ip, host, recv_data, sent_data):
        if client_ip not in self.clients:
            self.clients.update({client_ip: {host: (recv_data, sent_data)}})
        elif host not in self.clients[client_ip]:
            self.clients[client_ip].update({host: (recv_data, sent_data)})
        else:
            data_info = self.clients[client_ip][host]
            prev_recv_data = data_info[0]
            prev_sent_data = data_info[1]
            new_data_info = (prev_recv_data + recv_data,
                             prev_sent_data + sent_data)
            self.clients[client_ip][host] = new_data_info

    def get_formatted_stats(self):
        result = ''
        for client_ip in self.clients:
            for host in self.clients[client_ip]:
                data_info = self.clients[client_ip][host]
                info = '{} - {}; Client received: {}, Client sent: {} \n'.format(
                    client_ip, host, data_info[0], data_info[1])
                if info:
                    result += info

        return result

    def print_formatted_statistics(self):
        print(self.get_formatted_stats())
