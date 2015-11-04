//translate([0,0,4.3]) MFRC522();

$fn=30;

difference() {
    hull() {
        translate([30,30,0]) cylinder(r=5, h=12);
        translate([-30,30,0]) cylinder(r=5, h=12);
        translate([30,-20,0]) cylinder(r=5, h=12);
        translate([-30,-20,0]) cylinder(r=5, h=12);
    }
    translate([0,5,11]) cube([62,52,20], center=true);
    cylinder(r=1,h=0.5);
    difference() {
        union() {
            difference() {
                cylinder(r=5,h=0.5);
                cylinder(r=4,h=0.5);
            }
            difference() {
                cylinder(r=10,h=0.5);
                cylinder(r=9,h=0.5);
            }
            difference() {
                cylinder(r=15,h=0.5);
                cylinder(r=14,h=0.5);
            }
            difference() {
                cylinder(r=20,h=0.5);
                cylinder(r=19,h=0.5);
            }
        }
    rotate([0,0,45]) cube(50);
    rotate([0,0,225]) cube(50);
    }
    translate([25,25,-0.1]) cylinder(r1=2.6, r2=1, h=2.2);
}
translate([25,25,0]) difference() {
    cylinder(r=4.5, h=7);
    translate([0,0,-0.1]) cylinder(r=2.6, h=10);
}
translate([-14,17.25,1]) difference() {
    cylinder(r=3, h=3);
    cylinder(r=1, h=20);
}
translate([-14,-17.25,1]) difference() {
    cylinder(r=3, h=3);
    cylinder(r=1, h=20);
}
translate([23,11.25,1]) difference() {
    cylinder(r=3, h=3);
    cylinder(r=1, h=20);
}
translate([23,-11.25,1]) difference() {
    cylinder(r=3, h=3);
    cylinder(r=1, h=20);
}
    

module MFRC522() {
    color("Blue") {
        difference() {
            cube([60,40,1.6], center=true);
            translate([-14,17.25,-10]) cylinder(r=2.65/2, h=20);
            translate([-14,-17.25,-10]) cylinder(r=2.65/2, h=20);
            translate([23,11.25,-10]) cylinder(r=2.65/2, h=20);
            translate([23,-11.25,-10]) cylinder(r=2.65/2, h=20);
        }
        translate([-28,0,15]) cube([4,22,30], center=true);
    }
}