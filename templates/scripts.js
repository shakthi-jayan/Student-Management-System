document.addEventListener('DOMContentLoaded', () => {
    const themeToggle = document.getElementById('themeToggle');
    const darkIcon = document.getElementById('darkIcon');
    const lightIcon = document.getElementById('lightIcon');
    const themeText = document.getElementById('themeText');
    const html = document.documentElement;

    // Check for saved theme preference or use system preference
    const savedTheme = localStorage.getItem('theme');
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    const initialTheme = savedTheme || (prefersDark ? 'dark' : 'light');

    // Apply initial theme
    html.classList.remove('light', 'dark');
    html.classList.add(initialTheme);
    updateThemeUI(initialTheme);

    // Toggle theme on button click
    if (themeToggle) {
        themeToggle.addEventListener('click', () => {
            const currentTheme = html.classList.contains('dark') ? 'dark' : 'light';
            const newTheme = currentTheme === 'dark' ? 'light' : 'dark';

            html.classList.remove('light', 'dark');
            html.classList.add(newTheme);
            localStorage.setItem('theme', newTheme);
            updateThemeUI(newTheme);
            updateChartColors();
        });
    }

    // Update UI elements based on theme
    function updateThemeUI(theme) {
        if (theme === 'dark') {
            darkIcon.classList.add('hidden');
            lightIcon.classList.remove('hidden');
            themeText.textContent = 'Light Mode';
        } else {
            darkIcon.classList.remove('hidden');
            lightIcon.classList.add('hidden');
            themeText.textContent = 'Dark Mode';
        }
    }

    // Listen for system theme changes
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (e) => {
        if (!localStorage.getItem('theme')) {
            const newTheme = e.matches ? 'dark' : 'light';
            html.classList.remove('light', 'dark');
            html.classList.add(newTheme);
            updateThemeUI(newTheme);
            updateChartColors();
        }
    });

    // Register chartjs-plugin-datalabels
    if (typeof Chart !== 'undefined' && typeof ChartDataLabels !== 'undefined') {
        Chart.register(ChartDataLabels);
    } else {
        console.warn('Chart.js or ChartDataLabels plugin not loaded properly.');
    }

    // Initialize charts with proper data
    try {
        // Parse data from template variables with validation
        let courses, fees, studentCounts, coursePerformance, courseEnrollment, enrollmentTrends;
        try {
            courses = JSON.parse(document.getElementById('courses-data')?.textContent || '[]') || [];
        } catch (e) {
            console.warn('Failed to parse courses:', e.message);
            courses = [];
        }
        try {
            fees = JSON.parse(document.getElementById('fees-data')?.textContent || '[]') || [];
        } catch (e) {
            console.warn('Failed to parse fees:', e.message);
            fees = [];
        }
        try {
            studentCounts = JSON.parse(document.getElementById('student-counts-data')?.textContent || '[]') || [];
        } catch (e) {
            console.warn('Failed to parse student_counts:', e.message);
            studentCounts = [];
        }
        try {
            coursePerformance = JSON.parse(document.getElementById('course-performance-data')?.textContent || '[]') || [];
        } catch (e) {
            console.warn('Failed to parse course_performance:', e.message);
            coursePerformance = [];
        }
        try {
            courseEnrollment = JSON.parse(document.getElementById('course-enrollment-data')?.textContent || '{}') || {};
        } catch (e) {
            console.warn('Failed to parse course_enrollment:', e.message);
            courseEnrollment = {};
        }
        try {
            enrollmentTrends = JSON.parse(document.getElementById('enrollment-trends-data')?.textContent || '[]') || [];
        } catch (e) {
            console.warn('Failed to parse enrollment_trends:', e.message);
            enrollmentTrends = [];
        }

        // Parse numeric values with fallback
        const collectedRevenue = parseFloat(document.getElementById('collected-revenue-data')?.textContent || '0') || 0;
        const pendingPayments = parseFloat(document.getElementById('pending-payments-data')?.textContent || '0') || 0;
        const totalRevenue = parseFloat(document.getElementById('total-revenue-data')?.textContent || '0') || 0;

        // Chart color configuration
        const getThemeColors = () => {
            return html.classList.contains('dark') ? {
                text: '#E5E7EB',
                grid: '#4B5563',
                feesBackground: 'rgba(34, 197, 94, 0.2)',
                feesBorder: 'rgba(34, 197, 94, 1)',
                studentsBackground: 'rgba(249, 115, 22, 0.2)',
                studentsBorder: 'rgba(249, 115, 22, 1)',
                revenueCollected: '#34D399',
                revenuePending: '#FB923C',
                enrollment: '#6366F1',
                revenue: '#34D399',
                cumulative: '#FB923C'
            } : {
                text: '#6B7280',
                grid: '#E5E7EB',
                feesBackground: 'rgba(16, 185, 129, 0.2)',
                feesBorder: 'rgba(16, 185, 129, 1)',
                studentsBackground: 'rgba(234, 88, 12, 0.2)',
                studentsBorder: 'rgba(234, 88, 12, 1)',
                revenueCollected: '#10B981',
                revenuePending: '#F97316',
                enrollment: '#4F46E5',
                revenue: '#10B981',
                cumulative: '#F97316'
            };
        };

        // Initialize charts
        let colors = getThemeColors();
        let courseChart, revenuePieChart, courseEnrollmentChart, courseRevenueChart, revenueTrendChart, enrollmentTrendChart;

        // Course Chart (Course Report)
        const courseChartCanvas = document.getElementById('courseChart');
        if (courseChartCanvas && courses.length > 0 && fees.length > 0 && scholarCounts.length > 0) {
            courseChart = new Chart(courseChartCanvas, {
                type: 'bar',
                data: {
                    labels: courses,
                    datasets: [
                        {
                            label: 'Total Fees Collected (₹)',
                            data: fees,
                            backgroundColor: colors.feesBackground,
                            borderColor: colors.feesBorder,
                            borderWidth: 1,
                            yAxisID: 'y'
                        },
                        {
                            label: 'Students Enrolled',
                            data: studentCounts,
                            backgroundColor: colors.studentsBackground,
                            borderColor: colors.studentsBorder,
                            borderWidth: 1,
                            yAxisID: 'y1'
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'top',
                            labels: {
                                color: colors.text,
                                padding: 20,
                                font: {
                                    size: 12
                                }
                            }
                        },
                        title: {
                            display: true,
                            text: 'Course Enrollment and Fee Collection',
                            color: colors.text,
                            font: {
                                size: 16
                            }
                        }
                    },
                    scales: {
                        y: {
                            beginAtZero: true,
                            position: 'left',
                            title: {
                                display: true,
                                text: 'Fees (₹)',
                                color: colors.text
                            },
                            ticks: {
                                color: colors.text
                            },
                            grid: {
                                color: colors.grid
                            }
                        },
                        y1: {
                            beginAtZero: true,
                            position: 'right',
                            title: {
                                display: true,
                                text: 'Students',
                                color: colors.text
                            },
                            ticks: {
                                color: colors.text
                            },
                            grid: {
                                drawOnChartArea: false,
                                color: colors.grid
                            }
                        },
                        x: {
                            title: {
                                display: true,
                                text: 'Courses',
                                color: colors.text
                            },
                            ticks: {
                                color: colors.text,
                                maxRotation: 45,
                                minRotation: 45
                            },
                            grid: {
                                display: false
                            }
                        }
                    }
                }
            });
        } else if (courseChartCanvas) {
            console.warn('Course Chart: Canvas found but insufficient data.');
        }

        // Revenue Pie Chart (Analytics Dashboard)
        const revenuePieCanvas = document.getElementById('revenuePieChart');
        if (revenuePieCanvas) {
            revenuePieChart = new Chart(revenuePieCanvas, {
                type: 'pie',
                data: {
                    labels: ['Collected', 'Pending'],
                    datasets: [{
                        data: [collectedRevenue, pendingPayments],
                        backgroundColor: [colors.revenueCollected, colors.revenuePending],
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: {
                                color: colors.text,
                                padding: 20,
                                font: {
                                    size: 12
                                }
                            }
                        },
                        title: {
                            display: true,
                            text: 'Revenue Distribution',
                            color: colors.text,
                            font: {
                                size: 16
                            }
                        },
                        datalabels: {
                            formatter: (value) => {
                                return '₹' + value.toLocaleString() + '\n(' + 
                                    (totalRevenue > 0 ? (value / totalRevenue * 100).toFixed(1) : 0) + '%)';
                            },
                            color: '#fff',
                            font: {
                                weight: 'bold'
                            }
                        }
                    }
                }
            });
        }

        // Course Enrollment Chart (Analytics Dashboard)
        const courseEnrollmentCanvas = document.getElementById('courseEnrollmentChart');
        if (courseEnrollmentCanvas && Object.keys(courseEnrollment).length > 0) {
            const courseLabels = Object.keys(courseEnrollment);
            const enrollmentData = Object.values(courseEnrollment);

            courseEnrollmentChart = new Chart(courseEnrollmentCanvas, {
                type: 'bar',
                data: {
                    labels: courseLabels,
                    datasets: [{
                        label: 'Students',
                        data: enrollmentData,
                        backgroundColor: colors.enrollment,
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            display: false
                        },
                        title: {
                            display: true,
                            text: 'Course Enrollments',
                            color: colors.text,
                            font: {
                                size: 16
                            }
                        }
                    },
                    scales: {
                        x: {
                            ticks: {
                                color: colors.text,
                                maxRotation: 45,
                                minRotation: 45
                            },
                            grid: {
                                display: false
                            }
                        },
                        y: {
                            beginAtZero: true,
                            ticks: {
                                color: colors.text
                            },
                            grid: {
                                color: colors.grid
                            }
                        }
                    }
                }
            });
        }

        // Course Revenue Chart (Analytics Dashboard)
        const courseRevenueCanvas = document.getElementById('courseRevenueChart');
        if (courseRevenueCanvas && coursePerformance.length > 0) {
            const courseLabels = coursePerformance.map(item => item.course || 'Unknown');
            const revenueData = coursePerformance.map(item => item.total_fees || 0);

            courseRevenueChart = new Chart(courseRevenueCanvas, {
                type: 'bar',
                data: {
                    labels: courseLabels,
                    datasets: [{
                        label: 'Revenue',
                        data: revenueData,
                        backgroundColor: colors.revenue,
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            display: false
                        },
                        title: {
                            display: true,
                            text: 'Course Revenue',
                            color: colors.text,
                            font: {
                                size: 16
                            }
                        }
                    },
                    scales: {
                        x: {
                            ticks: {
                                color: colors.text,
                                maxRotation: 45,
                                minRotation: 45
                            },
                            grid: {
                                display: false
                            }
                        },
                        y: {
                            beginAtZero: true,
                            ticks: {
                                color: colors.text,
                                callback: function(value) {
                                    return '₹' + value;
                                }
                            },
                            grid: {
                                color: colors.grid
                            }
                        }
                    }
                }
            });
        }

        // Revenue Trend Chart (Analytics Dashboard)
        const revenueTrendCanvas = document.getElementById('revenueTrendChart');
        if (revenueTrendCanvas && enrollmentTrends.length > 0) {
            const revenueDates = enrollmentTrends.map(item => item.date || '');
            const revenueData = enrollmentTrends.map(item => item.revenue || 0);

            revenueTrendChart = new Chart(revenueTrendCanvas, {
                type: 'line',
                data: {
                    labels: revenueDates,
                    datasets: [{
                        label: 'Revenue',
                        data: revenueData,
                        borderColor: colors.enrollment,
                        backgroundColor: 'rgba(79, 70, 229, 0.1)',
                        borderWidth: 2,
                        fill: true,
                        tension: 0.2
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            display: false
                        },
                        title: {
                            display: true,
                            text: 'Revenue Trend',
                            color: colors.text,
                            font: {
                                size: 16
                            }
                        }
                    },
                    scales: {
                        x: {
                            ticks: {
                                color: colors.text
                            },
                            grid: {
                                display: false
                            }
                        },
                        y: {
                            beginAtZero: true,
                            ticks: {
                                color: colors.text,
                                callback: function(value) {
                                    return '₹' + value;
                                }
                            },
                            grid: {
                                color: colors.grid
                            }
                        }
                    }
                }
            });
        }

        // Enrollment Trend Chart (Analytics Dashboard)
        const enrollmentTrendCanvas = document.getElementById('enrollmentTrendChart');
        if (enrollmentTrendCanvas && enrollmentTrends.length > 0) {
            const enrollmentDates = enrollmentTrends.map(item => item.date || '');
            const enrollmentData = enrollmentTrends.map(item => item.enrollments || 0);
            
            // Calculate cumulative enrollments
            let cumulativeData = [];
            let cumulative = 0;
            for (let enrollment of enrollmentData) {
                cumulative += enrollment;
                cumulativeData.push(cumulative);
            }

            enrollmentTrendChart = new Chart(enrollmentTrendCanvas, {
                type: 'line',
                data: {
                    labels: enrollmentDates,
                    datasets: [
                        {
                            label: 'Enrollments',
                            data: enrollmentData,
                            borderColor: colors.enrollment,
                            backgroundColor: 'rgba(79, 70, 229, 0.1)',
                            borderWidth: 2,
                            fill: true,
                            tension: 0.2
                        },
                        {
                            label: 'Cumulative Enrollments',
                            data: cumulativeData,
                            borderColor: colors.cumulative,
                            backgroundColor: 'rgba(251, 146, 60, 0.1)',
                            borderWidth: 2,
                            fill: true,
                            tension: 0.2
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'top',
                            labels: {
                                color: colors.text,
                                padding: 20,
                                font: {
                                    size: 12
                                }
                            }
                        },
                        title: {
                            display: true,
                            text: 'Enrollment Trend',
                            color: colors.text,
                            font: {
                                size: 16
                            }
                        }
                    },
                    scales: {
                        x: {
                            ticks: {
                                color: colors.text
                            },
                            grid: {
                                display: false
                            }
                        },
                        y: {
                            beginAtZero: true,
                            ticks: {
                                color: colors.text
                            },
                            grid: {
                                color: colors.grid
                            }
                        }
                    }
                }
            });
        }

        // Function to update chart colors based on theme
        function updateChartColors() {
            colors = getThemeColors();

            if (courseChart) {
                courseChart.data.datasets[0].backgroundColor = colors.feesBackground;
                courseChart.data.datasets[0].borderColor = colors.feesBorder;
                courseChart.data.datasets[1].backgroundColor = colors.studentsBackground;
                courseChart.data.datasets[1].borderColor = colors.studentsBorder;
                courseChart.options.plugins.legend.labels.color = colors.text;
                courseChart.options.plugins.title.color = colors.text;
                courseChart.options.scales.y.title.color = colors.text;
                courseChart.options.scales.y.ticks.color = colors.text;
                courseChart.options.scales.y.grid.color = colors.grid;
                courseChart.options.scales.y1.title.color = colors.text;
                courseChart.options.scales.y1.ticks.color = colors.text;
                courseChart.options.scales.x.title.color = colors.text;
                courseChart.options.scales.x.ticks.color = colors.text;
                courseChart.update();
            }

            if (revenuePieChart) {
                revenuePieChart.data.datasets[0].backgroundColor = [colors.revenueCollected, colors.revenuePending];
                revenuePieChart.options.plugins.legend.labels.color = colors.text;
                revenuePieChart.options.plugins.title.color = colors.text;
                revenuePieChart.update();
            }

            if (courseEnrollmentChart) {
                courseEnrollmentChart.data.datasets[0].backgroundColor = colors.enrollment;
                courseEnrollmentChart.options.plugins.title.color = colors.text;
                courseEnrollmentChart.options.scales.x.ticks.color = colors.text;
                courseEnrollmentChart.options.scales.y.ticks.color = colors.text;
                courseEnrollmentChart.options.scales.y.grid.color = colors.grid;
                courseEnrollmentChart.update();
            }

            if (courseRevenueChart) {
                courseRevenueChart.data.datasets[0].backgroundColor = colors.revenue;
                courseRevenueChart.options.plugins.title.color = colors.text;
                courseRevenueChart.options.scales.x.ticks.color = colors.text;
                courseRevenueChart.options.scales.y.ticks.color = colors.text;
                courseRevenueChart.options.scales.y.grid.color = colors.grid;
                courseRevenueChart.update();
            }

            if (revenueTrendChart) {
                revenueTrendChart.data.datasets[0].borderColor = colors.enrollment;
                revenueTrendChart.data.datasets[0].backgroundColor = 'rgba(79, 70, 229, 0.1)';
                revenueTrendChart.options.plugins.title.color = colors.text;
                revenueTrendChart.options.scales.x.ticks.color = colors.text;
                revenueTrendChart.options.scales.y.ticks.color = colors.text;
                revenueTrendChart.options.scales.y.grid.color = colors.grid;
                revenueTrendChart.update();
            }

            if (enrollmentTrendChart) {
                enrollmentTrendChart.data.datasets[0].borderColor = colors.enrollment;
                enrollmentTrendChart.data.datasets[0].backgroundColor = 'rgba(79, 70, 229, 0.1)';
                enrollmentTrendChart.data.datasets[1].borderColor = colors.cumulative;
                enrollmentTrendChart.data.datasets[1].backgroundColor = 'rgba(251, 146, 60, 0.1)';
                enrollmentTrendChart.options.plugins.legend.labels.color = colors.text;
                enrollmentTrendChart.options.plugins.title.color = colors.text;
                enrollmentTrendChart.options.scales.x.ticks.color = colors.text;
                enrollmentTrendChart.options.scales.y.ticks.color = colors.text;
                enrollmentTrendChart.options.scales.y.grid.color = colors.grid;
                enrollmentTrendChart.update();
            }
        }

        // Initialize progress bars
        document.querySelectorAll('[data-width]').forEach(el => {
            el.style.width = `${el.dataset.width}%`;
        });
        document.querySelectorAll('[data-percentage]').forEach(progressBar => {
            const percentage = parseFloat(progressBar.dataset.percentage);
            progressBar.style.width = `${percentage}%`;
        });
    } catch (error) {
        console.error('Error initializing charts:', error);
    }
});