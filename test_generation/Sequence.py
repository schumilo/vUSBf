#!/usr/bin/python
"""
    vUSBf: A KVM/QEMU based USB-fuzzing framework.
    Copyright (C) 2015  Sergej Schumilo, OpenSource Security Ralf Spenneberg
    This file is part of vUSBf.

    See the file LICENSE for copying permission.
"""
__author__ = 'Sergej Schumilo'

class Sequence(object):
    def __init__(self):
        pass

    def next(self):
        pass

    def reset(self):
        pass

    def __mul__(a, b):
        return ProductSequence(a, b)

    def __add__(a, b):
        return ChainSequence(a, b)

    def __mod__(a, b):
        return LinkSequence(a, b)

    def __iter__(self):
        return SequenceIter(self)

    def __len__(self):
        return 12


class SequenceIter(object):
    def __init__(self, seq):
        self.len_value = len(seq)
        self.seq = seq

    def next(self):
        n = self.seq.next()
        if n == None:
            raise StopIteration
        return n

    def __len__(self):
        return self.len_value


class ListSequence(Sequence):
    def __init__(self, list):
        self.len_value = len(list)
        self.__list = list
        self.__pos = 0

    def next(self):
        if len(self.__list) == self.__pos:
            # self.reset()
            return None
        n = self.__list[self.__pos]
        self.__pos += 1
        return n

    def reset(self):
        self.__pos = 0

    def __len__(self):
        return self.len_value


class GeneratorSequence(Sequence):
    def __init__(self, gen):
        self.__gen = gen
        self.reset()

    def next(self):
        try:
            return self.__g.next()
        except StopIteration:
            return None

    def reset(self):
        self.__g = self.__gen()

    def __len__(self):
        return 1


class ChainSequence(GeneratorSequence):
    def __init__(self, *sequences):
        self.__sequences = []
        for s in sequences:
            if type(s) == list:
                s = ListSequence(s)
            self.__sequences.append(s)
            self.len_value = 0
            for e in self.__sequences:
                self.len_value += len(e)
        gen = lambda: self.gen_seq(self.__sequences)
        super(ChainSequence, self).__init__(gen)

    def gen_seq(self, sequences):
        for s in sequences:
            while True:
                e = s.next()
                if e == None:
                    break
                yield e

    def reset(self):
        super(ChainSequence, self).reset()
        for s in self.__sequences:
            s.reset()

    def __len__(self):
        return self.len_value


class LinkSequence(GeneratorSequence):
    def __init__(self, *sequences):
        self.__sequences = []
        for s in sequences:
            if type(s) == list:
                s = ListSequence(s)
            self.__sequences.append(s)
            self.len_value = 0
            for e in self.__sequences:
                if self.len_value == 0:
                    self.len_value = len(e)
                else:
                    if self.len_value > len(e):
                        self.len_value = len(e)
        gen = lambda: self.gen_seq(self.__sequences)
        super(LinkSequence, self).__init__(gen)

    def gen_seq(self, sequences):
        linked_value = []
        while True:
            linked_value = []
            for s in sequences:
                var = s.next()
                if var == None:
                    return
                linked_value.append(var)
            yield self.flatten(linked_value)

    def reset(self):
        super(LinkSequence, self).reset()
        for s in self.__sequences:
            s.reset()

    def flatten(self, x):
        result = []
        for el in x:
            if hasattr(el, "__iter__") and not isinstance(el, basestring):
                result.extend(self.flatten(el))
            else:
                result.append(el)
        return result

    def __len__(self):
        return self.len_value


class ProductSequence(GeneratorSequence):
    def __init__(self, *sequences):
        self.__sequences = []
        for s in sequences:
            if type(s) == list:
                s = ListSequence(s)
            self.__sequences.append(s)
            self.len_value = 1
            # len
            for e in self.__sequences:
                self.len_value *= len(e)
        if len(sequences) == 2:
            gen = lambda: self.gen_seq2(self.__sequences[0], self.__sequences[1])
        else:
            gen = lambda: self.gen_seqx(self.__sequences)

        super(ProductSequence, self).__init__(gen)

    def gen_seq2(self, s1, s2):
        res = []
        while 1:
            e1 = s1.next()
            if e1 == None:
                break
            res.append(e1)
            s2.reset()
            while 1:
                e2 = s2.next()
                if e2 == None:
                    break
                res.append(e2)
                yield self.flatten(res)
                res.pop()
            res.pop()

    def gen_seqx(self, sequences):
        seq = ProductSequence(sequences[0], sequences[1]);
        for n in range(2, len(sequences)):
            seq = ProductSequence(seq, sequences[n]);
        while True:
            res = seq.next();
            if res == None:
                break;
            yield self.flatten(res);

    def reset(self):
        super(ProductSequence, self).reset()
        for s in self.__sequences:
            s.reset()

    def flatten(self, x):
        result = []
        for el in x:
            if hasattr(el, "__iter__") and not isinstance(el, basestring):
                result.extend(self.flatten(el))
            else:
                result.append(el)
        return result

    def __len__(self):
        return self.len_value


def S(*x):
    # print type(x)
    #if type(x) != tuple and type(x) != list:
    #	print "EXIT"
    #	return x

    if len(x) == 1 and (isinstance(x[0], Sequence)):
        return x[0]

    if len(x) == 1 and type(x[0]) == list:
        x = x[0]
    else:
        x = list(x)
    return ListSequence(x)

# some testing stuff up here
if __name__ == "__main__":
    #
    list1 = ['A', 'B', 'C']
    list2 = ['X', 'Y']
    list3 = ['1', '2', '3', '4']

    # Sequence
    a = S(1, 2)
    print "LEN:" + str(len(a))
    for x in a:
        print x
    print "--------------"
    # ChainSequence
    # a = S(1,2,3) * S(446) * S(list2) * S(list3)
    a = S(1, 2) * S(3, 4)
    print "LEN:" + str(len(a))
    for x in a:
        print x
    print "--------------"

    # ProductSequence
    a = S(1, 2) + S(3, 4)
    print "LEN:" + str(len(a))
    for x in a:
        print x
    print "--------------"

    # LinkSequence
    a = (S(1, 2) % S(3, 4))
    #print "-> " + str(type(a))
    #a = S(a)
    #a = S(a)
    #print "-> " + str(type(a))
    print "LEN:" + str(len(a))
    for x in a:
        print x

