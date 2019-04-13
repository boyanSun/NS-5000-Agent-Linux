#!/usr/bin/env python
# -*- coding:utf-8 -*-
'''
@date: 20167-06-29
@author: qilongyun
'''
import logging
import logging.config

#日志级别大小关系为：CRITICAL > ERROR > WARNING > INFO > DEBUG > NOTSET，当然也可以自己定义日志级别。

class AgentLog(object):
    '''
    def __init__(self):
        logging.config.fileConfig( "logger.conf" )
        self.logger = logging.getLogger( "agentlog" )

    def getLogger(self):
        return self

    def error(self, msg):
        msg = "[ %s ] [Failed]"%(str(msg))
        self.logger.error(msg)

    def warning(self, msg):
        msg = "[ %s ] [Success]"%(str(msg))
        self.logger.warning(msg)

    def info(self, msg):
        msg = "[ %s ] [Success]"%(str(msg))
        self.logger.info(msg)
    '''

    def getLogger(self):
        # PLZ use the absolute path for configure file
        logging.config.fileConfig("logger.conf")
        logger = logging.getLogger("agentlog")
        return logger
