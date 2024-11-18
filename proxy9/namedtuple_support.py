import inspect
import logging
import os
import sys
import weakref
from contextlib import suppress
from collections.abc import (
    Buffer,
    Mapping,
    Collection,
    Iterable,
    Set,
    MutableSequence,
    MutableSet,
    Sequence,
)
from enum import IntFlag
from typing import (
    NamedTuple,
    Any,
    TypeGuard,
)


_ExtendedAsDictImplTypes = weakref.WeakSet()
_UnknownAsDictImplTypes = weakref.WeakSet()
_namedtuple_type_cache = weakref.WeakSet()

root_logger = logger = logging.getLogger(
    __name__ if __name__ != "__main__" else f"{os.path.splitext(__file__)[0]}"
)


def isinstance_namedtuple(obj) -> TypeGuard[NamedTuple]:
    if type(obj) in _namedtuple_type_cache:
        return True
    if (
        type(obj) is not tuple
        and isinstance(obj, tuple)
        and hasattr(obj, "_asdict")
        and hasattr(obj, "_fields")
    ):
        _namedtuple_type_cache.add(type(obj))
        return True
    return False


def isitemtuple[K, V](item: tuple) -> TypeGuard[tuple[K, V]]:
    return type(item) is tuple and len(item) == 2


def _warn_or_log(*args, **kwargs):
    logger.warning(*args, **kwargs)
    root = logging.getLogger("")
    if not any(handler for a_logger in (logger, root) for handler in a_logger.handlers):
        print("warning", args[0], file=sys.stderr, flush=True)


def _items_iterable_from[K, V](item: Mapping[K, V]) -> Iterable[tuple[K, V]]:
    match item:
        case dict():
            mapping_iterable = item.items()
        case Mapping() if callable(getattr(item, "keys", None)):
            mapping_iterable = ((key, item[key]) for key in item.keys())
        case Mapping():
            for item_or_key in item:
                if isitemtuple(item_or_key):
                    mapping_iterable = item
                else:
                    mapping_iterable = ((key, item[key]) for key in item)
                break
        case Iterable() if not isinstance(item, (str, Buffer)):
            for item_or_key in item:
                if isitemtuple(item_or_key):
                    mapping_iterable = item
                else:
                    mapping_iterable = ((key, item[key]) for key in item)
                break
        case _:
            raise TypeError(type(item).__qualname__)

    return mapping_iterable


def _asdict_contains_for_mapping[K, V](item: Mapping[K, V], *, cls=None) -> bool:
    if cls is None:
        cls = tuple(_ExtendedAsDictImplTypes)
    for key, value in _items_iterable_from(item):
        pair = (key, value)
        if any(
            any((isinstance(element, cls), isinstance_namedtuple(element))) for element in pair
        ):
            return True
        match value:
            case list() | set() | tuple() | frozenset():
                iterable = value
                return any(
                    any((isinstance(element, cls), isinstance_namedtuple(element)))
                    for element in iterable
                )
            case Collection() if not isinstance(value, (Buffer, str)):
                iterable = value
                return any(
                    any((isinstance(element, cls), isinstance_namedtuple(element)))
                    for element in iterable
                )
            case _:
                continue
    return False


class RecursiveMeta(type):
    __slots__ = ()

    def default(self, item, /, **kwargs):
        reg = tuple(_ExtendedAsDictImplTypes)
        match item:
            case named_tuple if isinstance(named_tuple, reg):
                return named_tuple._asdict(**kwargs)
            case other_named_tuple if isinstance_namedtuple(other_named_tuple):
                del item
                cls = type(other_named_tuple)
                if kwargs and cls not in _UnknownAsDictImplTypes:
                    try:
                        obj = other_named_tuple._asdict(**kwargs)
                    except TypeError:
                        _UnknownAsDictImplTypes.add(cls)
                        return other_named_tuple._asdict()
                    else:
                        _ExtendedAsDictImplTypes.add(cls)
                        return obj
                return self.default(other_named_tuple._asdict(), **kwargs)
            case Mapping() if _asdict_contains_for_mapping((mapping := item), cls=reg):
                target = mapping.copy()
                for key, value in _items_iterable_from(mapping):
                    match value:
                        case Collection() if not isinstance(value, (Buffer, str)):
                            target[key] = self.default(value, **kwargs)
                        case _:
                            ...
                            # dest[key] = value
                return target
            case Sequence() if any(
                any((isinstance(element, reg), isinstance_namedtuple(element))) for element in item
            ):
                iterable = item
                del item
                cast_cls = None
                if isinstance(iterable, MutableSequence):
                    dest_iterable = iterable[:]
                else:
                    dest_iterable = list(iterable)
                    cast_cls = type(iterable)
                for index, element in enumerate(iterable):
                    match element:
                        case named_tuple if isinstance(named_tuple, reg):
                            obj = named_tuple._asdict(**kwargs)
                        case other_named_tuple if isinstance_namedtuple(other_named_tuple):
                            cls = type(element)
                            if kwargs and cls not in _UnknownAsDictImplTypes:
                                try:
                                    obj = other_named_tuple._asdict(**kwargs)
                                except TypeError:
                                    _UnknownAsDictImplTypes.add(cls)
                                    obj = self.default(other_named_tuple._asdict(), **kwargs)
                                else:
                                    _ExtendedAsDictImplTypes.add(cls)
                            else:
                                obj = self.default(other_named_tuple._asdict(), **kwargs)
                        case Collection() if not isinstance(element, (Buffer, str)):
                            obj = cls.default(element, **kwargs)
                        case _:
                            continue
                    if element is not obj:
                        dest_iterable[index] = obj
                if cast_cls is not None:
                    return cast_cls(dest_iterable)
                return dest_iterable
            case Set() if any(
                any((isinstance(element, reg), isinstance_namedtuple(element))) for element in item
            ):
                cast_cls = None
                a_set = item
                del item
                if isinstance(a_set, MutableSet):
                    dest_set = a_set.copy()
                else:
                    dest_set = set(a_set)
                    cast_cls = type(a_set)
                for element in a_set:
                    match element:
                        case named_tuple if isinstance(named_tuple, reg):
                            obj = named_tuple._asdict(**kwargs)
                        case other_named_tuple if isinstance_namedtuple(other_named_tuple):
                            cls = type(element)
                            if kwargs and cls not in _UnknownAsDictImplTypes:
                                try:
                                    obj = other_named_tuple._asdict(**kwargs)
                                except TypeError:
                                    _UnknownAsDictImplTypes.add(cls)
                                    obj = self.default(other_named_tuple._asdict(), **kwargs)
                                else:
                                    _ExtendedAsDictImplTypes.add(cls)
                            else:
                                obj = self.default(other_named_tuple._asdict(), **kwargs)
                        case Collection() if not isinstance(element, (Buffer, str)):
                            obj = cls.default(element, **kwargs)
                        case _:
                            continue
                    if obj is not element:
                        dest_set.discard(element)
                        dest_set.add(obj)
                if cast_cls is not None:
                    return cast_cls(dest_set)
                return dest_set
        return item


_track_property_names: Mapping[type, tuple[str, ...]] = weakref.WeakKeyDictionary()


class TrackProperty:
    __slots__ = ()

    def __init_subclass__(cls, *args, **kwargs):
        _track_property_names[cls] = list_properties_for(cls)
        return super().__init_subclass__(*args, **kwargs)


def list_properties_for(instance: Any) -> tuple[str, ...]:
    if isinstance(instance, type):
        cls = instance
    else:
        cls = type(instance)
    if issubclass(cls, TrackProperty):
        with suppress(KeyError):
            return _track_property_names[cls]
    names = []
    for attr_name in dir(cls):
        if isinstance(inspect.getattr_static(cls, attr_name, None), property):
            names.append(attr_name)
    return tuple(names)


class Serialization(IntFlag):
    DEFAULT = NONE = 0
    INCLUDES_PROPERTIES = 2
    NO_RECURSE = 4


class RecursiveAsDict(metaclass=RecursiveMeta):
    __slots__ = ()

    def __init_subclass__(cls):
        index = cls.mro().index(RecursiveAsDict)
        before = cls.mro()[1:index]
        non_covered_asdict_cls = tuple(
            parent
            for parent in before
            if hasattr(parent, "_asdict") and not isinstance(cls, RecursiveMeta)
        )
        if non_covered_asdict_cls:
            _warn_or_log(f"{cls.__qualname__} has {before} defined before {cls.__qualname__}")
        _ExtendedAsDictImplTypes.add(cls)
        return super().__init_subclass__()

    def _asdict_postprocess_(self, obj, /, **kwargs):
        cls = type(self)
        for key, value in obj.items():
            obj[key] = cls.default(value, **kwargs)
        return obj

    def _asdict(self, *, options: Serialization = Serialization.DEFAULT, **kwargs):
        default = super()._asdict()
        if options & Serialization.NO_RECURSE:
            return default
        return self._asdict_postprocess_(default, **kwargs)


class CalculatedAsDict(TrackProperty):
    """
    When you want to include properties on the ``_asdict`` call
    """

    __slots__ = ()

    def _asdict(self, *, options=Serialization.DEFAULT, **kwargs):
        cls = type(self)
        values = super()._asdict(options=options, **kwargs)
        if options & Serialization.INCLUDES_PROPERTIES:
            for attr_name in list_properties_for(self):
                attr_value = getattr(self, attr_name)
                values[attr_name] = cls.default(attr_value, options=options, **kwargs)
        return values


class EnhancedSerialize(CalculatedAsDict, RecursiveAsDict):
    __slots__ = ()
