package me.amigoscode.springboothelper.controller;

import java.util.Arrays;
import java.util.List;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import me.amigoscode.springboothelper.model.Student;

@RestController
@RequestMapping("api/student-controller")
public class StudentController {
	
	private static final List<Student> STUDENTS = Arrays.asList(
		      new Student(1, "James Bond"),
		      new Student(2, "Maria Jones"),
		      new Student(3, "Anna Smith")
		    );

    @GetMapping(path = "{studentId}")
    /*
     *  to check if antMatcher does not allow access for ADMIN roles,
     *  then can this annotation allow ? the answer is it does not allow since everything is checked
     */
//    @PreAuthorize("hasAnyRole('ROLE_ADMIN')")
    public Student getStudent(@PathVariable("studentId") Integer studentId) {
        return STUDENTS.stream()
                .filter(student -> studentId.equals(student.getStudentId()))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException(
                        "Student " + studentId + " does not exists"
                ));
    }
}
