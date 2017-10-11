package core

import (
	"reflect"
	"testing"
	"time"
)

func IDsToStrings(ids []ID) []string {
	idStrings := make([]string, len(ids))
	for i, id := range ids {
		idStrings[i] = id.String()
	}
	return idStrings
}

func TestTimeRange(t *testing.T) {
	start, err := time.Parse(time.RFC822Z, "28 Dec 17 21:00 +0000")
	if err != nil {
		t.Fatal(err)
	}
	end, err := time.Parse(time.RFC822Z, "01 Mar 19 06:00 +0000")
	if err != nil {
		t.Fatal(err)
	}

	times := TimeRange(start, end)
	timeStrings := IDsToStrings(times)
	expectedTimeStrings := []string{"2017/12/28/21", "2017/12/28/22",
		"2017/12/28/23", "2017/12/29", "2017/12/30", "2017/12/31", "2018",
		"2019/1", "2019/2", "2019/3/1/0", "2019/3/1/1", "2019/3/1/2",
		"2019/3/1/3", "2019/3/1/4", "2019/3/1/5", "2019/3/1/6"}

	if !reflect.DeepEqual(timeStrings, expectedTimeStrings) {
		t.Fatal("Time IDs in output are incorrect")
	}
}

func TestTimeRangeOneDay(t *testing.T) {
	start, err := time.Parse(time.RFC822Z, "10 Oct 17 00:00 +0000")
	if err != nil {
		t.Fatal(err)
	}
	end, err := time.Parse(time.RFC822Z, "10 Oct 17 23:00 +0000")
	if err != nil {
		t.Fatal(err)
	}

	times := TimeRange(start, end)
	timeStrings := IDsToStrings(times)
	expectedTimeStrings := []string{"2017/10/10"}

	if !reflect.DeepEqual(timeStrings, expectedTimeStrings) {
		t.Fatal("Time IDs in output are incorrect")
	}
}

func TestTimeRangeTwoDays(t *testing.T) {
	start, err := time.Parse(time.RFC822Z, "10 Oct 17 00:00 +0000")
	if err != nil {
		t.Fatal(err)
	}
	end, err := time.Parse(time.RFC822Z, "11 Oct 17 23:00 +0000")
	if err != nil {
		t.Fatal(err)
	}

	times := TimeRange(start, end)
	timeStrings := IDsToStrings(times)
	expectedTimeStrings := []string{"2017/10/10", "2017/10/11"}

	if !reflect.DeepEqual(timeStrings, expectedTimeStrings) {
		t.Fatal("Time IDs in output are incorrect")
	}
}

func TestTimeRangeSingle(t *testing.T) {
	start, err := time.Parse(time.RFC822Z, "10 Oct 17 18:00 +0000")
	if err != nil {
		t.Fatal(err)
	}
	end, err := time.Parse(time.RFC822Z, "10 Oct 17 18:00 +0000")
	if err != nil {
		t.Fatal(err)
	}

	times := TimeRange(start, end)
	timeStrings := IDsToStrings(times)
	expectedTimeStrings := []string{"2017/10/10/18"}

	if !reflect.DeepEqual(timeStrings, expectedTimeStrings) {
		t.Fatal("Time IDs in output are incorrect")
	}
}

func TestTimeRangeTwoHours(t *testing.T) {
	start, err := time.Parse(time.RFC822Z, "10 Oct 17 18:00 +0000")
	if err != nil {
		t.Fatal(err)
	}
	end, err := time.Parse(time.RFC822Z, "10 Oct 17 19:00 +0000")
	if err != nil {
		t.Fatal(err)
	}

	times := TimeRange(start, end)
	timeStrings := IDsToStrings(times)
	expectedTimeStrings := []string{"2017/10/10/18", "2017/10/10/19"}

	if !reflect.DeepEqual(timeStrings, expectedTimeStrings) {
		t.Fatal("Time IDs in output are incorrect")
	}
}

func TestTimeRangeFebruary(t *testing.T) {
	start, err := time.Parse(time.RFC822Z, "28 Feb 16 23:00 +0000")
	if err != nil {
		t.Fatal(err)
	}
	end, err := time.Parse(time.RFC822Z, "02 Mar 16 00:00 +0000")
	if err != nil {
		t.Fatal(err)
	}

	times := TimeRange(start, end)
	timeStrings := IDsToStrings(times)
	expectedTimeStrings := []string{"2016/2/28/23", "2016/2/29", "2016/3/1", "2016/3/2/0"}

	if !reflect.DeepEqual(timeStrings, expectedTimeStrings) {
		t.Fatal("Time IDs in output are incorrect")
	}
}
