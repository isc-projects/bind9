
#ifndef ISC_EVENT_H
#define ISC_EVENT_H 1

/***
 *** Registry of Predefined Event Type Classes
 ***/

/*
 * An event class is a 16 bit number, the most sigificant bit of which must be
 * zero.  Each class may contain up to 65536 events.  An event type is
 * formed by adding the event number within the class to the class number.
 * E.g., the first event in the timer class is ISC_EVENTCLASS_TIMER + 1.
 * Event number zero is always reserved in each class.
 */

#define ISC_EVENTCLASS(class)		((class) << 16)

#define	ISC_EVENTCLASS_TASK		ISC_EVENTCLASS(0)
#define	ISC_EVENTCLASS_TIMER		ISC_EVENTCLASS(1)
#define	ISC_EVENTCLASS_SOCKET		ISC_EVENTCLASS(2)
#define	ISC_EVENTCLASS_FILE		ISC_EVENTCLASS(3)

/*
 * Event classes >= 1024 and <= 32767 are reserved for application use.
 */

#endif /* ISC_EVENT_H */
