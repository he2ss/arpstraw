import Queue
import re


def blacklist_oracle(sql_lines_queue, config_dico, decision_queue, prod_evt, evt):
    """
    this function print what it get from the queue,
    if the payload match in the query
    :return:
    """

    while True:
        try:
            item = sql_lines_queue.get(timeout=1)
        except Queue.Empty:
            if prod_evt.is_set():
                break
            else:
                continue
        if 'query' in item:
            for payload in blacklist:
                try:
                    res = payload.search(item['query'])
                    if res.group():
                        decision_queue.put((payload.pattern, str(item)))
                except AttributeError:
                    continue
    evt.set()