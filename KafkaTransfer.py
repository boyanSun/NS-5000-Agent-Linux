#!/usr/bin/env python
# -*- coding: utf-8 -*-

from kafka import KafkaProducer
from kafka import KafkaConsumer
from kafka.errors import KafkaError
from AgentLog import AgentLog

PrntLog= AgentLog().getLogger()

class Kafka_producer(object):
    '''
    使用kafka的生产模块
    '''
    def __init__(self, kafkahost,kafkaport, kafkatopic):
        self.kafkaHost = kafkahost
        self.kafkaPort = kafkaport
        self.kafkatopic = kafkatopic
        self.producer = KafkaProducer(bootstrap_servers = '{kafka_host}:{kafka_port}'.format(
            kafka_host=self.kafkaHost,
            kafka_port=self.kafkaPort
            ))

    def sendmsg(self, params):
        try:
            parmas_message = params
            producer = self.producer
            #producer.send(self.kafkatopic, parmas_message)
            producer.send( self.kafkatopic, parmas_message ).get(timeout=10)
            producer.flush()
        except KafkaError as e:
            PrntLog.error('sendmsg %s'%e)
            #print( 'sendmsg %s' % e )

class Kafka_consumer(object):
    '''
    使用Kafka—python的消费模块
    '''

    def __init__(self, kafkahost, kafkaport, kafkatopic, groupid):
        self.kafkaHost = kafkahost
        self.kafkaPort = kafkaport
        self.kafkatopic = kafkatopic
        self.groupid = groupid
        self.consumer = KafkaConsumer(self.kafkatopic, group_id = self.groupid,
                                      bootstrap_servers = '{kafka_host}:{kafka_port}'.format(
            kafka_host=self.kafkaHost,
            kafka_port=self.kafkaPort ))

    def consume_data(self):
        try:
            for message in self.consumer:
                # print json.loads(message.value)
                yield message
        except KeyboardInterrupt, e:
            PrntLog.error( 'consume_data %s'%e )
            #print( 'consume_data %s' % e )
