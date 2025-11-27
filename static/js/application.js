// application.js - Fixed with proper data handling

$(document).ready(function(){
    console.log('🚀 Application starting...');
    
    // ==========================================
    // SocketIO Connection
    // ==========================================
    var socket = io.connect('http://' + document.domain + ':' + location.port + '/test');
    var messages_received = [];

    socket.on('connect', function() {
        console.log('✓ Connected to server');
    });

    socket.on('disconnect', function() {
        console.log('✗ Disconnected from server');
    });

    // ==========================================
    // Chart.js Configuration
    // ==========================================
    var ctx = document.getElementById("myChart");
    var myChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                data: [],
                backgroundColor: [],
                borderColor: [],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            legend: {
                display: false
            },
            scales: {
                yAxes: [{
                    ticks: {
                        beginAtZero: true,
                        fontColor: '#e0e0e0'
                    },
                    gridLines: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    }
                }],
                xAxes: [{
                    ticks: {
                        fontColor: '#e0e0e0'
                    },
                    gridLines: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    }
                }]
            }
        }
    });

    // ==========================================
    // Map Configuration
    // ==========================================
    let myLocation = null;
    const ipMarkers = {};
    const ipLocations = {};
    const connectionLines = [];

    // Initialize Leaflet Map
    var ipMap = L.map('ipMap', {
        center: [20, 0],
        zoom: 2,
        minZoom: 2,
        maxZoom: 10,
        zoomControl: true
    });

    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        attribution: '&copy; OpenStreetMap',
        subdomains: 'abcd',
        maxZoom: 19
    }).addTo(ipMap);

    console.log('✓ Map initialized');

    // Get user location
    setTimeout(function() {
        if (navigator.geolocation) {
            navigator.geolocation.getCurrentPosition(
                function(position) {
                    myLocation = {
                        latitude: position.coords.latitude,
                        longitude: position.coords.longitude,
                        country: 'Your Location',
                        city: 'Current Location',
                        countryCode: '🏠'
                    };
                    console.log('✓ Got your location:', myLocation.latitude, myLocation.longitude);
                },
                function(error) {
                    console.log('⚠ Location permission denied, using default');
                    myLocation = {
                        latitude: 7.2091,
                        longitude: 79.8358,
                        country: 'Sri Lanka',
                        city: 'Negombo',
                        countryCode: 'LK'
                    };
                }
            );
        } else {
            myLocation = {
                latitude: 7.2091,
                longitude: 79.8358,
                country: 'Sri Lanka',
                city: 'Negombo',
                countryCode: 'LK'
            };
        }
    }, 100);

    // ==========================================
    // Map Helper Functions
    // ==========================================

    function extractIP(ipHtml) {
        if (!ipHtml) return null;
        var tempDiv = document.createElement('div');
        tempDiv.innerHTML = ipHtml;
        var text = tempDiv.textContent || tempDiv.innerText || '';
        var ipMatch = text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
        return ipMatch ? ipMatch[0] : null;
    }

    function isPrivateIP(ip) {
        if (!ip) return true;
        var parts = ip.split('.').map(Number);
        if (parts.length !== 4) return true;
        
        if (parts[0] === 10) return true;
        if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
        if (parts[0] === 192 && parts[1] === 168) return true;
        if (parts[0] === 127) return true;
        if (parts[0] === 0) return true;
        
        return false;
    }

    function getFlagEmoji(countryCode) {
        if (!countryCode || countryCode === '??' || countryCode === '🏠') {
            return '🏴';
        }
        var code = countryCode.toUpperCase();
        if (code.length !== 2) return '🏴';
        var codePoints = code.split('').map(function(char) {
            return 127397 + char.charCodeAt();
        });
        return String.fromCodePoint.apply(String, codePoints);
    }

    function getIPLocation(ip, callback) {
        // Check cache first
        if (ipLocations[ip]) {
            callback(ipLocations[ip]);
            return;
        }

        // For private/local IPs, use user's location
        if (isPrivateIP(ip)) {
            console.log('Private IP ' + ip + ' - using local location');
            
            // Wait for myLocation to be set
            var attempts = 0;
            var checkLocation = setInterval(function() {
                attempts++;
                if (myLocation || attempts > 20) {
                    clearInterval(checkLocation);
                    if (myLocation) {
                        // Add small random offset for visualization
                        ipLocations[ip] = {
                            latitude: myLocation.latitude + (Math.random() - 0.5) * 0.1,
                            longitude: myLocation.longitude + (Math.random() - 0.5) * 0.1,
                            country: myLocation.country,
                            city: 'LAN',
                            countryCode: '🏠'
                        };
                        callback(ipLocations[ip]);
                    } else {
                        callback(null);
                    }
                }
            }, 100);
            return;
        }

        // Fetch public IP location
        console.log('🌍 Fetching location for ' + ip + '...');
        $.ajax({
            url: 'https://ipapi.co/' + ip + '/json/',
            type: 'GET',
            timeout: 5000,
            success: function(data) {
                if (data.latitude && data.longitude) {
                    ipLocations[ip] = {
                        latitude: data.latitude,
                        longitude: data.longitude,
                        country: data.country_name || 'Unknown',
                        city: data.city || 'Unknown',
                        countryCode: data.country_code || '??'
                    };
                    console.log('✓ Located ' + ip + ': ' + data.city + ', ' + data.country_name);
                    callback(ipLocations[ip]);
                } else {
                    console.warn('No location data for ' + ip);
                    callback(null);
                }
            },
            error: function(xhr, status, error) {
                console.warn('Failed to locate IP ' + ip + ':', error);
                callback(null);
            }
        });
    }

    function createPulsingMarker(color, isThreat) {
        var size = 30;
        var svg = '<svg width="' + size + '" height="' + size + '" viewBox="0 0 ' + size + ' ' + size + '" xmlns="http://www.w3.org/2000/svg">' +
            '<circle cx="' + (size/2) + '" cy="' + (size/2) + '" r="8" fill="' + color + '" opacity="0.3">' +
            '<animate attributeName="r" from="8" to="14" dur="1.5s" repeatCount="indefinite"/>' +
            '<animate attributeName="opacity" from="0.5" to="0" dur="1.5s" repeatCount="indefinite"/>' +
            '</circle>' +
            '<circle cx="' + (size/2) + '" cy="' + (size/2) + '" r="6" fill="' + color + '" stroke="white" stroke-width="2">' +
            '<animate attributeName="r" from="5" to="7" dur="1s" repeatCount="indefinite"/>' +
            '</circle>' +
            '</svg>';
        
        return L.divIcon({
            html: svg,
            className: 'pulsing-marker',
            iconSize: [size, size],
            iconAnchor: [size/2, size/2]
        });
    }

    function drawConnectionLine(sourceCoords, destCoords, color) {
        var line = L.polyline([sourceCoords, destCoords], {
            color: color,
            weight: 3,
            opacity: 0.7,
            dashArray: '10, 10',
            className: 'animated-line'
        }).addTo(ipMap);

        connectionLines.push(line);

        // Animate and fade out
        var opacity = 0.7;
        var fadeInterval = setInterval(function() {
            opacity -= 0.02;
            if (opacity <= 0) {
                clearInterval(fadeInterval);
                ipMap.removeLayer(line);
                var index = connectionLines.indexOf(line);
                if (index > -1) connectionLines.splice(index, 1);
            } else {
                line.setStyle({ opacity: opacity });
            }
        }, 200);
    }

    function addIPToMap(srcIpHtml, destIpHtml, classification) {
        var srcIp = extractIP(srcIpHtml);
        var destIp = extractIP(destIpHtml);

        console.log('🔍 Processing flow: ' + srcIp + ' → ' + destIp + ' [' + classification + ']');

        if (!srcIp || !destIp) {
            console.warn('❌ Missing IP addresses');
            return;
        }

        var isThreat = classification !== 'Benign';
        var color = isThreat ? '#ff4444' : '#00ff88';

        // Get source location
        getIPLocation(srcIp, function(srcLocation) {
            if (srcLocation && srcLocation.latitude && srcLocation.longitude) {
                var coords = [srcLocation.latitude, srcLocation.longitude];
                
                if (!ipMarkers[srcIp]) {
                    var icon = createPulsingMarker(color, isThreat);
                    var marker = L.marker(coords, { icon: icon }).addTo(ipMap);
                    var flag = getFlagEmoji(srcLocation.countryCode);
                    
                    marker.bindPopup(
                        '<div style="color: #e0e0e0; min-width: 200px;">' +
                        '<strong style="color: #00ffff;">' + flag + ' Source IP</strong><br>' +
                        '<strong>Address:</strong> ' + srcIp + '<br>' +
                        '<strong>Location:</strong> ' + srcLocation.city + ', ' + srcLocation.country + '<br>' +
                        '<strong>Status:</strong> <span style="color: ' + color + ';">' + classification + '</span>' +
                        '</div>'
                    );
                    
                    ipMarkers[srcIp] = marker;
                    console.log('✓ Added source marker: ' + srcIp);
                }

                // Get destination location
                getIPLocation(destIp, function(destLocation) {
                    if (destLocation && destLocation.latitude && destLocation.longitude) {
                        var destCoords = [destLocation.latitude, destLocation.longitude];
                        
                        if (!ipMarkers[destIp]) {
                            var destIcon = createPulsingMarker(color, isThreat);
                            var destMarker = L.marker(destCoords, { icon: destIcon }).addTo(ipMap);
                            var destFlag = getFlagEmoji(destLocation.countryCode);
                            
                            destMarker.bindPopup(
                                '<div style="color: #e0e0e0; min-width: 200px;">' +
                                '<strong style="color: #00ffff;">' + destFlag + ' Destination IP</strong><br>' +
                                '<strong>Address:</strong> ' + destIp + '<br>' +
                                '<strong>Location:</strong> ' + destLocation.city + ', ' + destLocation.country + '<br>' +
                                '<strong>Status:</strong> <span style="color: ' + color + ';">' + classification + '</span>' +
                                '</div>'
                            );
                            
                            ipMarkers[destIp] = destMarker;
                            console.log('✓ Added destination marker: ' + destIp);
                        }

                        // Draw connection line
                        drawConnectionLine(coords, destCoords, color);
                        console.log('✓ Drew connection line');
                    }
                });
            }
        });
    }

    // ==========================================
    // SocketIO Event Handler
    // ==========================================
    socket.on('newresult', function(msg) {
        console.log('📊 New result received');
        console.log('Result:', msg.result);
        console.log('IPs:', msg.ips);
        
        // Maintain a list of ten messages
        if (messages_received.length >= 10) {
            messages_received.shift();
        }
        messages_received.push(msg.result);

        // Update table
        var messages_string = '<tr><th>Flow ID</th><th>Src IP</th><th>Src Port</th><th>Dst IP</th><th>Dst Port</th><th>Protocol</th><th>Flow start time</th><th>Flow last seen</th><th>App name</th><th>PID</th><th>Prediction</th><th>Prob</th><th>Risk</th><th>Actions</th></tr>';

        for (var i = messages_received.length - 1; i >= 0; i--) {
            var row = messages_received[i];
            var classification = row[10] ? row[10].toString() : 'Unknown';
            var rowClass = (classification !== 'Benign') ? 'alert-row' : '';
            
            messages_string += '<tr class="' + rowClass + '">';
            for (var j = 0; j < row.length; j++) {
                messages_string += '<td>' + row[j].toString() + '</td>';
            }
            messages_string += '<td><a href="/flow-detail?flow_id=' + row[0].toString() + '">Detail</a></td></tr>';
        }
        $('#details').html(messages_string);
        console.log('✓ Table updated with ' + messages_received.length + ' flows');

        // Update chart
        if (msg.ips && msg.ips.length > 0) {
            myChart.data.labels = [];
            myChart.data.datasets[0].data = [];
            myChart.data.datasets[0].backgroundColor = [];
            myChart.data.datasets[0].borderColor = [];
            
            for (var i = 0; i < msg.ips.length; i++) {
                myChart.data.labels.push(msg.ips[i].SourceIP);
                myChart.data.datasets[0].data.push(msg.ips[i].count);
                myChart.data.datasets[0].backgroundColor.push('rgba(0, 255, 255, 0.2)');
                myChart.data.datasets[0].borderColor.push('rgba(0, 255, 255, 1)');
            }
            myChart.update();
            console.log('✓ Chart updated with ' + msg.ips.length + ' IPs');
        }

        // Add to map
        if (msg.result && msg.result.length >= 11) {
            var srcIp = msg.result[1];      // Src IP (with possible HTML)
            var destIp = msg.result[3];     // Dst IP (with possible HTML)
            var classification = msg.result[10]; // Classification
            
            // Extract classification text if it contains HTML
            if (typeof classification === 'string' && classification.indexOf('<') !== -1) {
                var tempDiv = document.createElement('div');
                tempDiv.innerHTML = classification;
                classification = tempDiv.textContent || tempDiv.innerText || classification;
            }
            
            console.log('Adding to map: ' + srcIp + ' → ' + destIp + ' [' + classification + ']');
            addIPToMap(srcIp, destIp, classification);
        }
    });

    console.log('✓ Application ready - waiting for network traffic...');
});