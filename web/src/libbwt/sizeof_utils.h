#ifndef STRUCT_SIZEOF_H
#define STRUCT_SIZEOF_H

#define sizeof_member(type, member) (sizeof( ((type){}).member ))

#define sizeof_array(arr) ( sizeof(arr)/sizeof(arr[0]) )

#endif //STRUCT_SIZEOF_H
