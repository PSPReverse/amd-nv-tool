from dataclasses import dataclass, field
from typing import List, Dict
from binascii import hexlify


class HexInt(int):
    def __repr__(self):
        return hex(self)


class HexBytes(bytes):
    def __repr__(self):
        # return f'len={hex(len(self))}, hexbytes=\'{hexlify(self).decode()}\''
        return hexlify(self).decode()

    def try_interpret(self):
        #s = self.decode('ascii', errors='backslashreplace')
        #ile = int.from_bytes(self, 'little')
        #ibe = int.from_bytes(self, 'big')
        res =  f'{self.__repr__()}\n'
        res += f'{self}'
        #res += f'str   : {s}\n'
        #res += f'i (le): {ile}\n'
        #res += f'i (be): {ibe}'
        return res


@dataclass
class Entry:
    context_id : HexInt
    sequence_nr : HexInt
    fields : List[HexBytes]

    @staticmethod
    def build(context_id, sequence_nr, fields):
        return Entry(
            HexInt(context_id),
            HexInt(sequence_nr),
            [HexBytes(field) for field in fields],
        )


    def try_interpret(self):
        res =  f'{self.context_id} {self.sequence_nr}'
        for (num, field) in enumerate(self.fields):
            res += f'\nField {num}:\n  '
            res += field.try_interpret().replace('\n','\n  ')
        return res

def map_by_context_id(entries : List[List[List[Entry]]]) -> Dict[int, List[HexBytes]]:
    result = dict()
    for nd in entries:
        for es in nd:
            for e in es:
                sequence = list()
                if result.get(e.context_id):
                    sequence = result[e.context_id]

                if len(sequence) + 1 > e.sequence_nr:
                    #assert sequence[e.sequence_nr-1] == e.fields
                    pass
                else:
                    for _ in range(len(sequence) + 1, e.sequence_nr):
                        sequence.append(None)
                    sequence.append(e.fields)
            
                result[e.context_id] = sequence
    return result





