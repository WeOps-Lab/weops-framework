import csv
import io

from kafka import KafkaProducer

from apps.syslog.constants import KAFKA_HOST, LOCAL_LOG_TOPIC


class KafkaService(object):
    def __init__(self):
        self.kafka_host = KAFKA_HOST
        self.kafka_topic = LOCAL_LOG_TOPIC

    def push_messages_to_kafka(self, messages: list):
        """推送数据到kafka"""
        # 创建生产者
        producer = KafkaProducer(bootstrap_servers=self.kafka_host)

        # 推送数据到 Kafka 主题
        for message in messages:
            producer.send(self.kafka_topic, value=message.encode())

        # 处理未发送的消息并关闭生产者连接
        producer.flush()

        producer.close()


class LogService(object):
    def __init__(self, file_stream, file_type, flak=False):
        self.file_stream = file_stream
        self.file_type = file_type
        self.flak = flak

    def bytes_to_string(self):
        """将bytes转换为string"""
        return io.TextIOWrapper(self.file_stream, encoding="utf-8")

    def get_log(self):
        """获取日志数据"""
        if self.file_type == "text/csv":
            return self.read_csv_file()
        else:
            return self.read_text_file()

    def read_csv_file(self):
        """将csv数据导入"""
        csv_data = csv.reader(self.file_stream)
        result = []
        # 如何flak为True，则首行作为key, 否则将每行数据拼接为字符串
        if self.flak:
            keys = []
            for row in csv_data:
                if not keys:
                    keys = row
                    continue
                item = {}
                for index, key in enumerate(keys):
                    item[key] = row[index]
                result.append(str(item))
        else:
            for row in csv_data:
                result.append(" ".join(row))
        return result

    def read_text_file(self):
        """将本地日志导入"""
        return self.file_stream.readlines()

    def push_log_to_kafka(self):
        """推送数据到kafka"""
        # 文件格式转换
        self.file_stream = self.bytes_to_string()
        # 获取日志数据
        messages = self.get_log()
        # 推送数据到kafka
        KafkaService().push_messages_to_kafka(messages)
