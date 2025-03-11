package com.aramolla.jwt.util;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Locale;

public class TimeConverter {

    private static final DateTimeFormatter DATE_TIME_FORMATTER =
        DateTimeFormatter.ofPattern("yyyy. M. d. a h:mm").withLocale(Locale.KOREAN);
    private static final DateTimeFormatter DATE_FORMATTER =
        DateTimeFormatter.ofPattern("yyyy. M. d.").withLocale(Locale.KOREAN);

    // <============= 날짜, 시간까지 있는 경우 ==========>
    public static String DatetimeToString(LocalDateTime localDateTime) {
        return localDateTime.format(DATE_TIME_FORMATTER);
    }
    public static LocalDateTime stringToDateTime(String strTime) {
        return LocalDateTime.parse(strTime, DATE_TIME_FORMATTER);
    }

    // <============= 날짜만 있는 경우 =============>
    public static String DateToString(LocalDate localDate) {
        return localDate.format(DATE_FORMATTER);
    }
    public static LocalDate stringToDate(String strTime) {
        return LocalDate.parse(strTime, DATE_FORMATTER);
    }
}

