
#ifndef ISC_EVENT_H
#define ISC_EVENT_H 1

/***
 *** Registry of Predefined Event Type Classes
 ***/

/*
 * An event class is a 16 bit number, the most sigificant bit of which must be
 * zero.  Each class may contain up to 65536 events.  An event type is
 * formed by adding the event number within the class to the class number.
 * E.g., the first event in the timer class is EVENT_CLASS_TIMER + 1.  Event
 * number zero is always reserved in each class.
 */

#define EVENT_CLASS(class)		((class) << 16)

#define	EVENT_CLASS_TASK		EVENT_CLASS(0)

#define	EVENT_CLASS_TIMER		EVENT_CLASS(1)
#define	EVENT_CLASS_NET			EVENT_CLASS(2)
#define	EVENT_CLASS_FILE		EVENT_CLASS(3)

/*
 * Event classes >= 1024 and <= 32767 are reserved for application use.
 */

#endif /* ISC_EVENT_H */
