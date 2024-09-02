package net.rec0de.alloyparser

import net.rec0de.alloyparser.bitmage.ByteOrder
import net.rec0de.alloyparser.bitmage.fromBytes
import java.util.Date

class KeyedArchiveDecoder {
    companion object {
        private val topKey = BPAsciiString("\$top")
        private val rootKey = BPAsciiString("root")
        private val objectsKey = BPAsciiString("\$objects")
        private val classKey = BPAsciiString("\$class")
        private val classNameKey = BPAsciiString("\$classname")

        fun isKeyedArchive(data: BPListObject): Boolean {
            val archiverKey = BPAsciiString("\$archiver")
            val expectedArchiver = BPAsciiString("NSKeyedArchiver")
            return data is BPDict && data.values.containsKey(archiverKey) && data.values[archiverKey] == expectedArchiver
        }

        fun decode(data: BPDict): BPListObject {
            // get offset of the root object in the $objects list
            val topDict = data.values[topKey]!! as BPDict

            // so, turns out the key for the top object is not ALWAYS "root" (but almost always?)
            val top = if(topDict.values.containsKey(rootKey))
                    topDict.values[rootKey]!! as BPUid
                // empty archive case
                else if (topDict.values.isEmpty()) {
                    return BPNull
                }
                else
                    topDict.values.values.first { it is BPUid } as BPUid // this is about as good as we can do?

            val topIndex = Int.fromBytes(top.value, ByteOrder.BIG)
            val objects = data.values[objectsKey]!! as BPArray

            val rootObj = objects.values[topIndex]
            val resolved = optionallyResolveObjectReference(rootObj, objects, listOf(topIndex))
            return transformSupportedClasses(resolved)
        }

        private fun optionallyResolveObjectReference(thing: CodableBPListObject, objects: BPArray, currentlyResolving: List<Int> = emptyList()): BPListObject {
            return when(thing) {
                is BPUid -> {
                    val id = Int.fromBytes(thing.value, ByteOrder.BIG)
                    if(currentlyResolving.contains(id))
                        RecursiveBacklink(id, null)
                    else
                        optionallyResolveObjectReference(objects.values[id], objects, currentlyResolving + id)
                }

                is BPArray -> TransientBPArray(thing.values.map { optionallyResolveObjectReference(it, objects, currentlyResolving) })
                is BPSet -> TransientBPSet(thing.entries, thing.values.map { optionallyResolveObjectReference(it, objects, currentlyResolving) })
                is BPDict -> {
                    // nested keyed archives will be decoded separately
                    if(isKeyedArchive(thing))
                        thing
                    else
                        TransientBPDict(thing.values.map {
                            Pair(optionallyResolveObjectReference(it.key, objects), optionallyResolveObjectReference(it.value, objects, currentlyResolving))
                        }.toMap())
                }
                else -> thing
            }
        }

        private fun transformSupportedClasses(thing: BPListObject): BPListObject {
            // decode nested archives
            if(isKeyedArchive(thing))
                return decode(thing as BPDict)

            return when(thing) {
                is RecursiveBacklink -> {
                    thing
                }
                is TransientBPArray -> {
                    val transformedValues = thing.values.map { transformSupportedClasses(it) }
                    if(transformedValues.all { it is CodableBPListObject })
                        BPArray(transformedValues.map { it as CodableBPListObject })
                    else
                        NSArray(transformedValues)
                }
                is TransientBPSet -> {
                    val transformedValues = thing.values.map { transformSupportedClasses(it) }
                    if(transformedValues.all { it is CodableBPListObject })
                        BPSet(thing.entries, transformedValues.map { it as CodableBPListObject })
                    else
                        NSArray(transformedValues)
                }
                is TransientBPDict -> {
                    if(thing.values.containsKey(classKey)) {
                        val className = ((thing.values[classKey] as TransientBPDict).values[classNameKey] as BPAsciiString).value
                        when(className) {
                            "NSDictionary", "NSMutableDictionary" -> {
                                val keyList = (thing.values[BPAsciiString("NS.keys")]!! as TransientBPArray).values.map { transformSupportedClasses(it) }
                                val valueList = (thing.values[BPAsciiString("NS.objects")]!! as TransientBPArray).values.map { transformSupportedClasses(it) }
                                val map = keyList.zip(valueList).toMap()
                                NSDict(map)
                            }
                            "NSMutableString", "NSString" -> {
                                val string = (thing.values[BPAsciiString("NS.string")]!! as BPAsciiString)
                                string
                            }
                            "NSMutableArray", "NSArray" -> {
                                val list = (thing.values[BPAsciiString("NS.objects")]!! as TransientBPArray).values.map { transformSupportedClasses(it) }
                                NSArray(list)
                            }
                            "NSMutableSet", "NSSet" -> {
                                val list = (thing.values[BPAsciiString("NS.objects")]!! as TransientBPArray).values.map { transformSupportedClasses(it) }
                                NSSet(list.toSet())
                            }
                            "NSData", "NSMutableData" -> {
                                val value = thing.values[BPAsciiString("NS.data")]!!

                                // why do some NSData objects contain an NSDict with a nested keyed archive?
                                if(isKeyedArchive(value)) {
                                    decode(value as BPDict)
                                }
                                else {
                                    val bytes = (value as BPData)
                                    NSData(bytes.value)
                                }
                            }
                            "NSDate" -> {
                                val timestamp = (thing.values[BPAsciiString("NS.time")]!! as BPReal).value
                                // NSDates encode time as seconds from Jan 01 2001, we convert to standard unix time here
                                NSDate(Date((timestamp*1000).toLong() + 978307200000))
                            }
                            "NSUUID" -> {
                                NSUUID((thing.values[BPAsciiString("NS.uuidbytes")]!! as BPData).value)
                            }
                            else -> {
                                val entries = thing.values.map { Pair(transformSupportedClasses(it.key), transformSupportedClasses(it.value)) }
                                val basic = entries.all { it.first is CodableBPListObject && it.second is CodableBPListObject }
                                if(basic)
                                    BPDict(entries.associate { Pair(it.first as CodableBPListObject, it.second as CodableBPListObject) })
                                else
                                    NSDict(entries.toMap())
                            }
                        }
                    }
                    else {
                        BPDict(thing.values.map { Pair(transformSupportedClasses(it.key) as CodableBPListObject, transformSupportedClasses(it.value) as CodableBPListObject) }.toMap())
                    }
                }
                else -> thing
            }
        }
    }
}