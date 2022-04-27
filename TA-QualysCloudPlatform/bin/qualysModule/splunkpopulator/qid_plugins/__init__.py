import os
import sys
import abc
import six

plugin_directory = os.path.realpath(os.path.dirname(__file__))
sys.path.append(plugin_directory)


class QIDParser():
    # : :type: list of BaseQIDParser
    PLUGINS = {}

    @staticmethod
    def load_plugins():
        for root, dirs, files in os.walk(plugin_directory):
            for name in files:
                if name.endswith(".py") and not name.startswith("__"):
                    name = name.split("/")[-1]
                    name = name.split(".py")[0]
                    if name.startswith('_'):
                        continue
                    if name.startswith('__'):
                        continue
                    __import__(name)

    @staticmethod
    def process(qid, host_id, detection_node, logger):

        """

        :param qid:
        :param detection_node: Element
        :rtype: basestring
        """
        if qid in QIDParser.PLUGINS:
            result_node = detection_node.find('RESULTS')
            if result_node is not None:
                return QIDParser.PLUGINS[qid]().parse(qid, host_id, detection_node, logger)


    @classmethod
    def plugin(parseCls, qid):

        def decorator(cls):
            if qid not in QIDParser.PLUGINS:
                QIDParser.PLUGINS[qid] = cls
            return cls

        return decorator


class BaseQIDParser(six.with_metaclass(abc.ABCMeta)):
    """
    Base class to extend for implementing parsers for QID results, to implement support for parsing a QID results
    extend this class and decorate it with @QIDParser.plugin(15018) where 15018 is QID for which parser is implemented
    Implement/Override parse(qid, results) method , where results is the result of QID, this method should return
    a Key=value string which will get appended to HOSTSUMMARY log line
    """

    def __init__(self):
        pass

    @abc.abstractmethod
    def parse(cls, qid, host_id, results, logger):
        """

        :param results: string
        :return:
        """
        return