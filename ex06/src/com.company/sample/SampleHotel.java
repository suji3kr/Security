package com.company.sample;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import lombok.Getter;
import lombok.ToString;

@Component
@ToString
@Getter
public class SampleHotel {

	private Chef chef;

	public SampleHotel(Chef chef) {
		this.chef = chef;
	}	
}
